Personal SDN project codes used for a journal paper
Steps to Run the SDN-Based Network Security Project on Mininet in Linux
1. Install Required Software
Operating System: Use a Linux-based OS (Ubuntu 20.04 recommended).
Mininet: Install Mininet, which allows for creating and managing virtual network topologies.
bash
Copy code
sudo apt-get update
sudo apt-get install mininet
Ryu Controller: Install the Ryu SDN controller, used for managing OpenFlow switches.
bash
Copy code
sudo pip install ryu
Python: Ensure Python 3 is installed, along with required dependencies.
bash
Copy code
sudo apt-get install python3 python3-pip
Git: Clone the project repository from GitHub.
bash
Copy code
git clone https://github.com/Pootes/SDN.git
cd SDN
2. Prepare the Simulation Environment
Network Topology:
Create a custom topology using Mininet scripts provided in the repository. Modify these scripts to suit your simulation needs if required.
Start Mininet with a basic topology:
bash
Copy code
sudo mn --controller=remote --topo=single,3
This creates a topology with one switch and three hosts.
Traffic Simulation:
Use hping3 or iperf to generate legitimate and malicious traffic for testing.
bash
Copy code
sudo apt-get install hping3
hping3 -S <target_ip> -p 80 --flood
3. Set Up the Ryu Controller
Navigate to the Ryu directory in the repository.
Run the Ryu controller with the custom application provided (e.g., DDoS detection app).
bash
Copy code
ryu-manager <path_to_controller_script>
4. Deploy and Test
Deploy the Topology: Run the Mininet script provided in the repository.
bash
Copy code
sudo python3 <topology_script>.py
Start Traffic: Initiate traffic from the hosts to simulate both legitimate and malicious behavior.
bash
Copy code
h1 ping h2
h3 hping3 -S h1 --flood
Monitor the Controller:
Open a separate terminal and monitor the controller's logs for detection messages.
bash
Copy code
tail -f /var/log/ryu/ryu-manager.log
5. Evaluate Results
Observe flow classifications in the controller logs. Ensure that malicious traffic is detected and mitigated (e.g., blocked or rate-limited).
Use Wireshark to capture and analyze traffic between the nodes.
bash
Copy code
sudo apt-get install wireshark
sudo wireshark &
