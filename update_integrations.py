import re

with open('backend/internal/scanner/integrations.go', 'r') as f:
    content = f.read()

# Remove emitCmd definition completely
content = re.sub(r'\n\temitCmd := func\(tool, args string\) \{.*?\n\t\}\n', '', content, flags=re.DOTALL)

# Insert runTool definition right where emitCmd was (or at the beginning of runOptionalIntegrations)
run_tool_def = '''runTool := func(tool, args string, fn func() []model.Finding) []model.Finding {
if input.Emit != nil {
input.Emit(model.ScanEvent{
Type:      model.ScanEventCommand,
AgentName: "scanner",
Command:   tool + " " + args,
Message:   fmt.Sprintf("Running integration tool: %s", tool),
})
}
res := s.runInstrumentedTool(ctx, tool, fn)
if input.Emit != nil {
input.Emit(model.ScanEvent{
Type:      model.ScanEventCommandResult,
AgentName: "scanner",
Command:   tool + " " + args,
Output:    fmt.Sprintf("[%s completed execution]", tool),
})
}
return res
}'''

content = re.sub(r'(\tstate := &integrationState\{SkippedReasons: map\[string\]int\{\}\}\n)', r'\1\n' + run_tool_def + '\n', content)

# Now replace the calls
# Match:
# emitCmd("tool", "args")
# findings = append(findings, s.runInstrumentedTool(ctx, "tool", func() []model.Finding { ... })...)

def repl(m):
    tool_arg1 = m.group(1)
    args_arg2 = m.group(2)
    tool_arg3 = m.group(3)
    fn_body = m.group(4)
    # Return replacing s.runInstrumentedTool with runTool
    return f'findings = append(findings, runTool({tool_arg1}, {args_arg2}, {fn_body})...)'

pattern = r'emitCmd\(([^,]+),\s*(.*?)\)\s*\n\s*findings = append\(findings, s\.runInstrumentedTool\(ctx,\s*([^,]+),\s*(func\(\)\s*\[\]model\.Finding\s*\{.*?\})\)\.\.\.\)'

content = re.sub(pattern, repl, content, flags=re.DOTALL)

with open('backend/internal/scanner/integrations.go', 'w') as f:
    f.write(content)

