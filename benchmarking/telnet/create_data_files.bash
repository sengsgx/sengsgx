#!/bin/bash
mkdir office_data
pushd office_data/

for i in `seq 99`
do
	touch "data_${i}"
done

dd ibs=1kB count=1 if=/dev/urandom of=nda_contract.txt

popd
