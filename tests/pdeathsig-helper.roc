app [main!] { pf: platform "../platform/main.roc" }

import pf.Cmd
import pf.Arg exposing [Arg]
import pf.Sleep

# Helper for PR_SET_PDEATHSIG test.
# Spawns "sleep 9999" via spawn_grouped! then sleeps forever.
# When this process is killed, "sleep 9999" should also die.

main! : List Arg => Result {} _
main! = |_args|
    # Spawn child via spawn_grouped! (sets PR_SET_PDEATHSIG)
    _ = Cmd.new("sleep") |> Cmd.args(["9999"]) |> Cmd.spawn_grouped!()?

    # Sleep forever - test will kill us
    Sleep.millis!(999999999)
    Ok({})
