#!/usr/bin/bash

# test project
nosetests tests/test.py -v -d --with-coverage --cover-package=ende,tests --cover-tests --cover-erase --cover-inclusive --cover-branches &> test.txt.temp

# test report
echo '' > test_report.txt
echo 'Ende Testing Report' >> test_report.txt
echo `date "+%Y-%m-%d %H:%M:%S %z"` >> test_report.txt
echo '=========================================' >> test_report.txt
echo '' >> test_report.txt
echo 'Test Report' >> test_report.txt
cat test.txt.temp >> test_report.txt

rm .coverage
rm test.txt.temp

echo 'project tested'
