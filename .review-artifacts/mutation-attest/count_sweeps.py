import importlib.util, itertools, json, pathlib, shutil, sys
import pytest

sys.path[:0]=[str(pathlib.Path("src").resolve())]
location=pathlib.Path("tests/test_attest.py").resolve()
spec=importlib.util.spec_from_file_location("test_attest_mutation",location)
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)
tmp=pathlib.Path(sys.argv[1]).resolve()
tmp.mkdir(parents=True,exist_ok=True)
histories={}
linear=tmp/"linear"
histories["linear"]=(linear,m._fixture_history(linear))
merged=tmp/"merged"
ids=m._fixture_history(merged)
m._fixture_git(merged,"checkout","--quiet","-b","side",ids["epoch"])
ids["side"]=m._fixture_commit(merged,"records/side.json","side",1_900_000_400)
m._fixture_git(merged,"checkout","--quiet","main")
m._fixture_git(merged,"merge","--quiet","--no-ff","-m","merge side","side",timestamp=1_900_000_500)
histories["merged"]=(merged,ids)
other=tmp/"other"
m._fixture_history(other,origin="Someone/else")
m._fixture_git(other,"reset","--quiet","--hard","HEAD~2")
grafts=tmp/"grafts"
values={"GIT_DIR":str(other/".git"),"GIT_OBJECT_DIRECTORY":str(other/".git"/"objects"),"GIT_GRAFT_FILE":str(grafts),"GIT_REPLACE_REF_BASE":"refs/elsewhere/"}
passed=0; failed=0; cases=[]
for name,(root,history) in histories.items():
    hidden=history["side"] if name=="merged" else history["unattested"]
    grafts.write_text(f"{history['unattested']}\n")
    expected=m._reference_records(root,f"{history['epoch']}..HEAD")
    assert hidden in expected
    for replaced in (False,True):
        if replaced:
            for ref in (f"refs/replace/{hidden}",f"refs/elsewhere/{hidden}"):
                parent=m._fixture_git(root,"rev-parse",f"{hidden}^")
                substitute=m._fixture_git(root,"commit-tree",m._fixture_git(root,"rev-parse",f"{parent}^{{tree}}"),"-p",parent,"-m","substitute")
                m._fixture_git(root,"update-ref",ref,substitute)
        for chosen in itertools.product((False,True),repeat=len(values)):
            with pytest.MonkeyPatch.context() as patch:
                for (variable,value),on in zip(values.items(),chosen):
                    if on: patch.setenv(variable,value)
                try:
                    checks=[m.repository_slug(root)=="MaxGhenis/brier",m.enforcement_epoch(root,spec=m._spec())==history["epoch"],m._in_scope(root)==expected]
                    ok=all(checks)
                    detail={"checks":checks}
                except Exception as exc:
                    ok=False
                    detail={"exception":type(exc).__name__,"message":str(exc)}
                passed+=int(ok); failed+=int(not ok)
                cases.append({"history":name,"replaced":replaced,"chosen":chosen,"pass":ok,**detail})
print(json.dumps({"passed":passed,"failed":failed,"total":passed+failed,"cases":cases},indent=2))
