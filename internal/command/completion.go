package command

import (
	"fmt"
	"sort"
	"strings"
)

// completionTree maps each command to its flags. Subcommand-bearing commands
// list their subcommands in completionSubcommands.
var completionTree = map[string][]string{
	"run":             {nameFlag, detachShort, detachFlag, imageFlag, templateShort, templateFlag, publishShort, publishFlag, allowFlag, denyFlag, cpusFlag, memoryShort, memoryFlag, envShort, envFlag, envFileFlag, removeFlag, newFlag, helpShort, helpFlag},
	"create":          {nameFlag, "--workspace", publishShort, publishFlag, allowFlag, denyFlag, templateShort, templateFlag, imageFlag, cpusFlag, memoryFlag, "--idempotency-key", envShort, envFlag, envFileFlag},
	"exec":            {"-i", "--interactive", "-t", "--tty", "-w", workdirFlag, envShort, envFlag, envFileFlag, "-u", userFlag},
	"cp":              {"-L", "--follow-link"},
	"ls":              {formatFlag, jsonFlag, "-q", "--quiet", "--limit"},
	"get":             {},
	"ports":           {formatFlag, jsonFlag, publishFlag, "--unpublish"},
	policyCommand:     {formatFlag, jsonFlag, sandboxFlag},
	startCommand:      {graceFlag, formatFlag, jsonFlag},
	stopCommand:       {graceFlag, formatFlag, jsonFlag},
	"rm":              {"-f", forceFlag, "--all", formatFlag, jsonFlag},
	"prune":           {"--dry-run", "-f", forceFlag, "--filter", formatFlag, jsonFlag},
	"diagnose":        {jsonFlag, formatFlag},
	"wait":            {},
	"login":           {usernameFlag, "--password-stdin"},
	"logout":          {forceFlag},
	secretCommand:     {"--registry", usernameFlag, "--password-stdin", "--all-sandboxes", sandboxFlag},
	"version":         {formatFlag, jsonFlag},
	completionCommand: {},
	"help":            {},
}

var completionSubcommands = map[string][]string{
	policyCommand:     {"ls", "inspect", "allow", "deny", "rm", "check", networkKeyword},
	secretCommand:     {"ls", "set", "rm"},
	completionCommand: {"bash", "zsh", "fish", "powershell"},
}

func completionCommands() []string {
	commands := make([]string, 0, len(completionTree))
	for name := range completionTree {
		commands = append(commands, name)
	}
	sort.Strings(commands)
	return commands
}

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
		return bashCompletionScript(), nil
	case "zsh":
		return zshCompletionScript(), nil
	case "fish":
		return fishCompletionScript(), nil
	case "powershell":
		return powershellCompletionScript(), nil
	default:
		return "", fmt.Errorf("unsupported shell %q", shell)
	}
}

func bashCompletionScript() string {
	var b strings.Builder
	b.WriteString(`# bash completion for ksbx
_ksbx_completion() {
  local cur prev cmd
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmd=""
  local i
  for ((i=1; i < COMP_CWORD; i++)); do
    case "${COMP_WORDS[i]}" in
      -*) ;;
      *) cmd="${COMP_WORDS[i]}"; break ;;
    esac
  done
  case "$prev" in
`)
	valueFlags := map[string]bool{}
	for _, name := range sortedKeys(completionTree) {
		for _, flag := range flagsTakingValue(completionTree[name]) {
			valueFlags[flag] = true
		}
	}
	var flags []string
	for flag := range valueFlags {
		flags = append(flags, flag)
	}
	sort.Strings(flags)
	fmt.Fprintf(&b, "    %s) COMPREPLY=(); return ;;\n", strings.Join(flags, "|"))
	b.WriteString(`  esac
  if [ -z "$cmd" ]; then
    COMPREPLY=( $(compgen -W "` + strings.Join(completionCommands(), " ") + `" -- "$cur") )
    return
  fi
  case "$cmd" in
`)
	for _, name := range sortedKeys(completionTree) {
		flags := completionTree[name]
		subs := completionSubcommands[name]
		words := append(append([]string{}, flags...), subs...)
		fmt.Fprintf(&b, "    %s) COMPREPLY=( $(compgen -W %q -- \"$cur\") );;\n", name, strings.Join(words, " "))
	}
	b.WriteString(`    *) COMPREPLY=() ;;
  esac
}
complete -F _ksbx_completion ksbx
`)
	return b.String()
}

func zshCompletionScript() string {
	var b strings.Builder
	b.WriteString("#compdef ksbx\n\n_ksbx() {\n  local -a commands\n  commands=(")
	b.WriteString(strings.Join(completionCommands(), " "))
	b.WriteString(")\n\n  local cmd\n  cmd=\"${words[2]}\"\n\n  case \"$cmd\" in\n")
	for _, name := range sortedKeys(completionTree) {
		words := make([]string, 0, len(completionTree[name])+len(completionSubcommands[name]))
		words = append(words, completionTree[name]...)
		words = append(words, completionSubcommands[name]...)
		if len(words) == 0 {
			fmt.Fprintf(&b, "    %s) _message 'no arguments' ;;\n", name)
			continue
		}
		fmt.Fprintf(&b, "    %s) _arguments '*: :(%s)' ;;\n", name, strings.Join(words, " "))
	}
	b.WriteString(`    *) _arguments '1: :($commands)' ;;
  esac
}

compdef _ksbx ksbx
`)
	return b.String()
}

func fishCompletionScript() string {
	var b strings.Builder
	b.WriteString("complete -c ksbx -f\n")
	for _, name := range completionCommands() {
		fmt.Fprintf(&b, "complete -c ksbx -n '__fish_use_subcommand' -a %s\n", name)
	}
	for _, name := range sortedKeys(completionTree) {
		for _, flag := range completionTree[name] {
			fmt.Fprintf(&b, "complete -c ksbx -n '__fish_seen_subcommand_from %s' -l %s\n", name, strings.TrimLeft(flag, "-"))
		}
		for _, sub := range completionSubcommands[name] {
			fmt.Fprintf(&b, "complete -c ksbx -n '__fish_seen_subcommand_from %s' -a %s\n", name, sub)
		}
	}
	return b.String()
}

func powershellCompletionScript() string {
	var b strings.Builder
	b.WriteString("Register-ArgumentCompleter -Native -CommandName ksbx -ScriptBlock {\n  param($wordToComplete, $commandAst, $cursorPosition)\n")
	b.WriteString("  $commands = @(")
	b.WriteString(strings.Join(quotedCommands(), ", "))
	b.WriteString(")\n")
	b.WriteString(`  $command = $commandAst.CommandElements[1].Value
  $words = $commands
  if ($commands -contains $command) {
    $words = switch ($command) {
`)
	for _, name := range sortedKeys(completionTree) {
		words := append(append([]string{}, completionTree[name]...), completionSubcommands[name]...)
		if len(words) == 0 {
			continue
		}
		quoted := make([]string, len(words))
		for i, w := range words {
			quoted[i] = fmt.Sprintf("%q", w)
		}
		fmt.Fprintf(&b, "      %q { @(%s) }\n", name, strings.Join(quoted, ", "))
	}
	b.WriteString(`      default { $commands }
    }
  }
  $words | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }
}
`)
	return b.String()
}

func sortedKeys(tree map[string][]string) []string {
	keys := make([]string, 0, len(tree))
	for key := range tree {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func quotedCommands() []string {
	commands := completionCommands()
	quoted := make([]string, len(commands))
	for i, command := range commands {
		quoted[i] = fmt.Sprintf("%q", command)
	}
	return quoted
}

// flagsTakingValue reports which flags of a command consume the next word.
func flagsTakingValue(flags []string) []string {
	valueFlags := map[string]bool{
		nameFlag: true, imageFlag: true, templateShort: true, templateFlag: true,
		publishShort: true, publishFlag: true, allowFlag: true, denyFlag: true,
		cpusFlag: true, memoryShort: true, memoryFlag: true, envShort: true, envFlag: true,
		envFileFlag: true, "--workspace": true, "--idempotency-key": true,
		"-w": true, workdirFlag: true, "-u": true, userFlag: true,
		formatFlag: true, "--limit": true, graceFlag: true, "--filter": true,
		usernameFlag: true, "--registry": true, sandboxFlag: true,
	}
	out := make([]string, 0, len(flags))
	for _, flag := range flags {
		if valueFlags[flag] {
			out = append(out, flag)
		}
	}
	return out
}
