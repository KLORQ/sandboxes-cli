package command

import (
	"fmt"
	"strings"
)

const completionCommands = "run create exec cp ls get ports policy start stop rm prune diagnose wait login logout secret version help"

func (r *Runner) completion(args []string) int {
	if len(args) == 1 && (args[0] == helpCommand || args[0] == helpShort || args[0] == helpFlag) {
		_, _ = fmt.Fprint(r.Out, "usage: ksbx completion bash|zsh|fish|powershell\n")
		return 0
	}
	if len(args) != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx completion bash|zsh|fish|powershell")
		return 2
	}
	script, err := completionScript(args[0])
	if err != nil {
		r.error(err)
		return 2
	}
	_, _ = fmt.Fprint(r.Out, script)
	return 0
}

func completionScript(shell string) (string, error) {
	switch shell {
	case "bash":
		return fmt.Sprintf(`_ksbx_completion() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W %q -- "$cur") )
}
complete -F _ksbx_completion ksbx
`, completionCommands), nil
	case "zsh":
		return fmt.Sprintf(`#compdef ksbx
_ksbx() {
  local -a commands
  commands=(%s)
  _describe 'command' commands
}
compdef _ksbx ksbx
`, strings.Join(strings.Fields(completionCommands), " ")), nil
	case "fish":
		return fmt.Sprintf("complete -c ksbx -f -a '%s'\n", completionCommands), nil
	case "powershell":
		return fmt.Sprintf(`Register-ArgumentCompleter -Native -CommandName ksbx -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  '%s'.Split(' ') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }
}
`, completionCommands), nil
	default:
		return "", fmt.Errorf("unsupported shell %q", shell)
	}
}
