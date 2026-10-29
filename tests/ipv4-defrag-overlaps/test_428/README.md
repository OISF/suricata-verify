# Test Description
Test the triplet of overlapping fragments (Oi,O,O), illustrated bellow.

![](./test_428.pdf)

## PCAP
Created with PYROLYSE (https://github.com/ANSSI-FR/pyrolyse)

## Redmine-related Tickets
https://redmine.openinfosecfoundation.org/issues/6668 
https://redmine.openinfosecfoundation.org/issues/6673
The tested Suricata versions reassemble the triplet of overlapping fragments (Oi,O,O) with a data hole: 001000no001001nn001002nm........000004ok. Consequently, Suricata is blind between fragment offsets 4 and 5 here. 


## Read more about overlapping data-related issues
https://arxiv.org/pdf/2504.21618
https://arxiv.org/pdf/2508.00735