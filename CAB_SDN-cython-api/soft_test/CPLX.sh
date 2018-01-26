#!/bin/bash
if [ "$1" = "-l" ]
then
    echo "H:Maximum split level  Using:8k_${2}" >> ./CPLX_test_results
    for i in {1..10}
    do
        echo "Running: 8k_${2} level:$i"
        ./build/CPLX_test -r ./ruleset/8k_${2} $i
    done
elif [ "$1" = "-s" ]
then
    echo "H:Ruleset size  Using:*k_${2}" >> ./CPLX_test_results
    for i in {1..20}
    do
        echo "Running: ${i}k_${2}"
        ./build/CPLX_test -r ./ruleset/${i}k_${2} 5
    done
else
    echo "usage: -l|-s smoothness"
fi

#!/bin/bash
#for j in 4 8 16 32
#do
#    echo "H:Maximum split level  Using:8k_${j}" >> ./CPLX_test_results
#    for i in {1..10}
#    do
#        echo "Running: 8k_${j} level:$i"
#        ./build/CPLX_test -r ./ruleset/8k_${j} $i
#    done
#done

#for j in 4 8 16 32
#do
#    echo "H:Ruleset size  Using:*k_${j}" >> ./CPLX_test_results
#    for i in {1..20}
#    do
#        echo "Running: ${i}k_${j}"
#        ./build/CPLX_test -r ./ruleset/${i}k_${j} 5
#    done
#done
