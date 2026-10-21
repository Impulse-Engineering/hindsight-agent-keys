#!/bin/bash
# Entrypoint of the hindsight-ui image: upstream's web UI only, one process per
# Team, never the API (README, "The UI image"). HINDSIGHT_UI_TEAMS lists
# "<team>:<port>" entries; each Team's key is HINDSIGHT_UI_KEY_<TEAM>, the name
# upper-cased with "-" as "_". When one UI process exits, the others are stopped
# and the container exits non-zero, so the platform restarts the whole set.
set -eu

problems=()
if [ $# -ne 0 ]; then
  problems+=("the image takes no command; it runs only the UI processes HINDSIGHT_UI_TEAMS lists")
fi

# -d '' reads every line, so an entry after a newline is never dropped unchecked.
read -r -d '' -a entries <<<"${HINDSIGHT_UI_TEAMS:-}" || true
if [ ${#entries[@]} -eq 0 ]; then
  problems+=("HINDSIGHT_UI_TEAMS is unset or empty; list each Team as <team>:<port>")
fi

declare -A team_of_port=() port_of_team=() key_var=()
teams=()
for entry in "${entries[@]}"; do
  if [[ ! $entry =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?):([1-9][0-9]{3,4})$ ]] ||
    ((BASH_REMATCH[3] < 1024 || BASH_REMATCH[3] > 65535)); then
    problems+=("'$entry' is not <team>:<port> (team: lowercase letters, digits and inner hyphens; port: 1024 to 65535)")
    continue
  fi
  team=${BASH_REMATCH[1]} port=${BASH_REMATCH[3]}
  if [ -n "${port_of_team[$team]:-}" ]; then
    problems+=("Team $team is listed twice")
  fi
  if [ -n "${team_of_port[$port]:-}" ]; then
    problems+=("port $port is listed for both ${team_of_port[$port]} and $team")
  fi
  var=HINDSIGHT_UI_KEY_$(tr 'a-z-' 'A-Z_' <<<"$team")
  if [ -z "${!var:-}" ]; then
    problems+=("$var, the key of Team $team, is unset or empty")
  fi
  team_of_port[$port]=$team port_of_team[$team]=$port key_var[$team]=$var
  teams+=("$team")
done

if [ ${#problems[@]} -ne 0 ]; then
  printf 'ui-start: refusing to start: %s\n' "${problems[@]}" >&2
  exit 78
fi

pids=()
stop() {
  kill "${pids[@]}" 2>/dev/null || true
  wait || true
}
trap 'stop; exit 0' TERM INT

cd /app/control-plane
for team in "${teams[@]}"; do
  var=${key_var[$team]}
  # Docker sets HOSTNAME to the container ID, and Next.js binds to HOSTNAME.
  HOSTNAME=0.0.0.0 PORT=${port_of_team[$team]} HINDSIGHT_CP_DATAPLANE_API_KEY=${!var} node server.js &
  pids+=("$!")
  echo "ui-start: Team $team on port ${port_of_team[$team]}"
done

status=0
wait -n || status=$?
echo "ui-start: a UI process exited with status $status; stopping the others" >&2
stop
exit $((status == 0 ? 1 : status))
