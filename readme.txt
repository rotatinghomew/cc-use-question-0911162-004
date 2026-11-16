跨境人工智能数据血缘与撤回影响控制台

运行验收：
python3 -m lineage_consent run --fixture fixtures/acceptance.json --database /tmp/lineage_consent.sqlite3 --output /tmp/lineage_consent-output

核验：
python3 -m lineage_consent verify --database /tmp/lineage_consent.sqlite3 --output /tmp/lineage_consent-output

全量测试：
python3 -m unittest discover -s tests -v

按模块测试：
python3 -m unittest tests.release_signal.test_release_risk -v

构建检查：
python3 -m compileall -q lineage_consent tests
