from pathlib import Path

path = Path('.github/scripts/apply-phase3.py')
text = path.read_text(encoding='utf-8')
old = '''marker = "        ActiveDefenseCommand::DefendRun { target, apply } => {"\n'''
new = '''marker = "            Ok(true)\\n        }\\n        ActiveDefenseCommand::DefendRun { target, apply } => {"\n'''
if text.count(old) != 1:
    raise SystemExit(f'expected one marker assignment, found {text.count(old)}')
text = text.replace(old, new, 1)
old_call = '''replace_once("src/active_defense/commands.rs", marker, phase3_arms + marker)'''
new_call = '''replace_once(\n    "src/active_defense/commands.rs",\n    marker,\n    "            Ok(true)\\n        }\\n" + phase3_arms + "        ActiveDefenseCommand::DefendRun { target, apply } => {",\n)'''
if text.count(old_call) != 1:
    raise SystemExit(f'expected one insertion call, found {text.count(old_call)}')
path.write_text(text.replace(old_call, new_call, 1), encoding='utf-8')
