# Test Description
Test the triplet of overlapping fragments (Oi,Si,O), illustrated bellow.

![](./test_435.pdf)

## PCAP
Created with PYROLYSE (https://github.com/ANSSI-FR/pyrolyse)

## Redmine-related Tickets
https://redmine.openinfosecfoundation.org/issues/6668 
https://redmine.openinfosecfoundation.org/issues/6673
The tested Suricata versions reassemble the triplet of overlapping fragments (Oi,Si,O) with a data hole: 001000no001001nn........000003ol. Consequently, Suricata is blind between fragment offsets 3 and 4 here. 


## Read more about overlapping data-related issues
https://arxiv.org/pdf/2504.21618
https://arxiv.org/pdf/2508.00735