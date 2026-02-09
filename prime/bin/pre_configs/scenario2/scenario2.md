# Scenario 2:
- Start with 2 control centers + 1 data center
- We lose 1 control center
- Move to singleton control center (on surviving control center)
- We lose the surviving control center
- We introduce the mobile control center and move to it (as singleton)
- We recover one of the original control centers and move to 2 control centers (one mobile) + data center

---

1. System initialized with 3 sites: 2 Control Centers (CC1, CC2) and 1 Data Center (DC). Each site runs 6 replicas.

2. Control Center 2 has failed.

3. System reconfigured: only CC1 remains active with 6 replicas.

4. Control Center 1 has failed. No active control centers remain.

5. Mobile Control Center (MCC) deployed and takes over as singleton control center.

6. Control Center 1 recovered. System reconfigured with MCC and CC1 as control centers.


# Title Card:

Scenario 2: Cascading Failures and Recovery via Mobile Control

This scenario highlights the system’s ability to recover from sequential failures of both control centers.

We begin with:

    2 Control Centers (CC1 and CC2)

    1 Data Center (DC)

    Each site running 6 replicas

We simulate a cascading failure:

    1. CC2 fails — system reconfigures to run solely on CC1

    2. CC1 then fails — no active control centers remain

To restore control:

    A Mobile Control Center (MCC) is deployed and takes over as a singleton control center

Finally:

    CC1 is recovered and the system reconfigures to a two-site control: MCC and CC1, alongside the Data Center
