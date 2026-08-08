from pathlib import Path

path = Path("tests/e2e_spec.rs")
text = path.read_text(encoding="utf-8")

old_import = "    memory::MemoryManager,\n    sandbox::Sandbox,"
new_import = "    memory::MemoryManager,\n    operations::OperationsStore,\n    sandbox::Sandbox,"
if text.count(old_import) != 1:
    raise SystemExit(f"expected one e2e import anchor, found {text.count(old_import)}")
text = text.replace(old_import, new_import, 1)

old_setup = "    evidence.init_schema().await?;\n\n    let signalgate = SignalGate::new(SignalGateConfig::default())?;"
new_setup = "    evidence.init_schema().await?;\n    let operations = OperationsStore::new(memory.pool.clone());\n\n    let signalgate = SignalGate::new(SignalGateConfig::default())?;"
if text.count(old_setup) != 1:
    raise SystemExit(f"expected one e2e setup anchor, found {text.count(old_setup)}")
text = text.replace(old_setup, new_setup, 1)

old_field = "        evidence_locker: evidence.clone(),\n        max_concurrent_payloads: 1,"
new_field = "        evidence_locker: evidence.clone(),\n        operations,\n        max_concurrent_payloads: 1,"
if text.count(old_field) != 1:
    raise SystemExit(f"expected one AgentLoopDeps anchor, found {text.count(old_field)}")
text = text.replace(old_field, new_field, 1)

path.write_text(text, encoding="utf-8")
