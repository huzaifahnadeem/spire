# Scenario 1: 
- Start with 2 control centers + 1 data center
- We lose 1 control center
- Move to singleton control center (on surviving control center)
- We add a mobile control center and move back to 2 control centers (1 is new mobile CC) and data center
- We recover the failed control center and move back to the original configuration 

--- 

1. The System is initialized with 3 sites: 2 Control Centers (CC1, CC2) and 1 Data Center (DC). Each site runs 6 replicas.

2. Control Center 2 has failed.

3. System reconfigured: only CC1 remains active with 6 replicas

4. Mobile Control Center (MCC) deployed to restore two-site control.

5. Original Control Center (CC2) recovered and reintegrated.


# Title Card:

Scenario 1: Control Center Failure and Full System Restoration

This scenario demonstrates the system’s ability to adapt to the loss of a control center and later return to its original configuration through seamless reconfiguration.

Initial State:

    2 Control Centers (CC1 and CC2)

    1 Data Center (DC)

    6 replicas per site

Sequence of Events:

    1. The system starts up with all three sites operational

    2. CC2 fails — the system reconfigures to operate with a singleton control center (CC1)

    3. A Mobile Control Center (MCC) is deployed to restore two-site control

    4. CC2 is recovered, and the system returns to its original configuration: CC1, CC2, and DC