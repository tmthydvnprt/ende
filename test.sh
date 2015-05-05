#!/usr/bin/bash

# test project
nosetests tests/test_data.py -v -d --with-coverage --cover-package=ende,tests --cover-tests --cover-erase --cover-inclusive --cover-branches &> test_data.txt.temp

# test project
nosetests tests/test_file.py -v -d --with-coverage --cover-package=ende,tests --cover-tests --cover-erase --cover-inclusive --cover-branches &> test_file.txt.temp

# test report
echo '' > test_report.txt
echo 'Ende Testing Report' >> test_report.txt
echo `date` >> test_report.txt
echo '=========================================' >> test_report.txt
echo '' >> test_report.txt
echo 'test_data Report' >> test_report.txt
cat test_data.txt.temp >> test_report.txt
echo 'test_file Report' >> test_report.txt
cat test_file.txt.temp >> test_report.txt

rm .coverage
rm test_data.txt.temp
rm test_file.txt.temp

echo 'project tested'
