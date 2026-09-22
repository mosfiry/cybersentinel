# CI run bfc419146dbc
result: FAILURE

## pytest failed (exit 1)
...............................................................F.....F.. [ 15%]
........................................................................ [ 30%]
........................................................................ [ 45%]
........................................................................ [ 61%]
........................................................................ [ 76%]
..............................s......................................... [ 91%]
........................................                                 [100%]
=================================== FAILURES ===================================
________________ test_decoy_name_cannot_poison_relation_queries ________________

    def test_decoy_name_cannot_poison_relation_queries():
        """The decoy entity's NAME contains a real CVE id, but traversal must not
        match it: queries follow typed relations only, never substrings."""
        g = build_graph_fixture()
        affected = g.products_affected_by("CVE-2021-44228")
        assert "log4j-2.14.1" in affected
>       assert "log4j-core" in affected
E       AssertionError: assert 'log4j-core' in ['log4j-2.14.1']

tests/test_cyber_knowledge_model.py:76: AssertionError
_____________ test_preconditions_and_detections_traverse_relations _____________

    def test_preconditions_and_detections_traverse_relations():
        g = build_graph_fixture()
        assert "prim-jndi" in g.evidence_for("chain-1")[0] or g.evidence_for("chain-1")
        detections = g.detections_for("CVE-2021-44228")
        assert detections == [], "CVE has ENABLES via chain? no: ENABLES only from chain, so direct is empty"
        chain_detections = g.detections_for("chain-1")
        assert "sig-1" in chain_detections
        assert g.preconditions_for("chain-1") == []
>       assert "log4j-core" in g.products_affected_by("CVE-2021-44228")
E       AssertionError: assert 'log4j-core' in ['log4j-2.14.1']
E        +  where ['log4j-2.14.1'] = products_affected_by('CVE-2021-44228')
E        +    where products_affected_by = <cyber.knowledge_model.CyberKnowledgeGraph object at 0x7f49f731be50>.products_affected_by

tests/test_cyber_knowledge_model.py:140: AssertionError
=========================== short test summary info ============================
FAILED tests/test_cyber_knowledge_model.py::test_decoy_name_cannot_poison_relation_queries - AssertionError: assert 'log4j-core' in ['log4j-2.14.1']
FAILED tests/test_cyber_knowledge_model.py::test_preconditions_and_detections_traverse_relations - AssertionError: assert 'log4j-core' in ['log4j-2.14.1']
 +  where ['log4j-2.14.1'] = products_affected_by('CVE-2021-44228')
 +    where products_affected_by = <cyber.knowledge_model.CyberKnowledgeGraph object at 0x7f49f731be50>.products_affected_by
2 failed, 469 passed, 1 skipped in 8.42s
