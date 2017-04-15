import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Scanner;

import javax.management.InvalidApplicationException;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class ids {
	
	public static void main(String[] args)
	{
		String policyFilePath;
		String pcapFilePath;
		
		final StringBuilder errbuf = new StringBuilder();
		
		//Check that both files have been supplied
		if(args.length == 2)
		{
			policyFilePath = args[0];
			pcapFilePath = args[1];
			
			System.out.println("Parsing policy file...");
			
			//Create PolicyFile object to store the information from the input policy file
			PolicyFile policy = new PolicyFile(policyFilePath);
			try
			{
				//Parse the file to set all the information
				policy.Parse();
			}
			catch(InvalidApplicationException e)
			{
				System.err.println("Error parsing the policy file.");
				return;
			}
			
			System.out.println("Opening Pcap File...");
			
			//Open the Pcap file
			Pcap pcap = Pcap.openOffline(pcapFilePath, errbuf);
			if (pcap == null) {
				 System.err.printf("Error while opening pcap file: " + errbuf.toString());
				 return;
			}
			
			//Create a handler for processing each packet in the pcap file
			PcapPacketHandler<String> pcapHandler = InitPcapHandler();
			
			try
			{
				//Loop through the entire pcap file via the handler
				pcap.loop(-1, pcapHandler, null);
			}
			finally
			{
				pcap.close();
			}
			
		}
		else
		{
			System.err.println("Please provided the policy file and the pcap trace file");
			System.err.println("Ex. java ids <policy-file> <pcap file>");
		}
	}
	
	/*
	 * Returns an instance of a PcapPacketHandler
	 * Next packet is called every time pcap.loop() is called
	 */
	static PcapPacketHandler<String> InitPcapHandler()
	{
		return new PcapPacketHandler<String>() {				
			public void nextPacket(PcapPacket packet, String user) {
					//Not implemented
			}
		};
	}
}

class PolicyFile
{
	String path;
	
	public String Host;
	public String PolicyName;
	public String StateType;
	public String Protocol;
	public String HostPort;
	public String AttackerPort;
	public String Attacker;
	public ArrayList<String> FromHosts;
	public ArrayList<String> ToHosts;
	
	public PolicyFile(String path)
	{
		this.path = path;
		FromHosts = new ArrayList<String>();
		ToHosts = new ArrayList<String>();
	}
	
	/*
	 * Parses the policy file, throws InvalidApplicationException if
	 * the file is not found or the syntax is incorrect.
	 */
	public void Parse() throws InvalidApplicationException
	{
		//Get the host name
		File file = new File(path);
		Scanner scan;
		try
		{
			scan = new Scanner(file);
		}
		catch(FileNotFoundException e)
		{
			System.err.println("Policy file not found");
			throw new InvalidApplicationException(this);
		}
		
		if(scan != null)
		{
			String curLine;
			
			while(scan.hasNextLine())
			{
				curLine = scan.nextLine();
				
				if(curLine.contains("host="))
				{
					this.Host = curLine.substring(5); 
				}
				else if(curLine.contains("name="))
				{
					this.PolicyName = curLine.substring(5);
				}
				else if(curLine.contains("type="))
				{
					this.StateType = curLine.substring(5);
				}
				else if(curLine.contains("proto="))
				{
					this.Protocol = curLine.substring(6);
				}
				else if(curLine.contains("host_port="))
				{
					this.HostPort = curLine.substring(10);
				}
				else if(curLine.contains("attacker_port="))
				{
					this.AttackerPort = curLine.substring(14);
				}
				else if(curLine.contains("attacker="))
				{
					this.Attacker = curLine.substring(9);
				}
				else if(curLine.contains("from_host="))
				{
					this.FromHosts.add(curLine.substring(10));
				}
				else if(curLine.contains("to_host="))
				{
					this.ToHosts.add(curLine.substring(8));
				}
			}
		}
		else
		{
			throw new InvalidApplicationException(this);
		}
	}
}
