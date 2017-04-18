
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;


public class IDS {
	static List<PcapPacket> packetslist=new ArrayList<PcapPacket>();

	static String  hostIP = null;
	static String name = null;
	static String type = null;
	static String proto = null;
	static String host_port;
	static String attackerIP = null;
	static String attacker_port;
	static String fromHost = null;
	static String toHost = null;
	static String fromHost1 = null;
	static String toHost1 = null;
	static String fromHost2 = null;
	static String statefulstr;
	static String statefulstr1;
	static Boolean flag1 = false, flag2 = false, flag3 = false, flag4 = false, flag5 = false;

	protected static int printc;
	
	public static void main(String args[]) {
		BufferedReader br = null;
		String line = null;
		String varType = null;
		String content;
		int index;
		int i = -1;
		int j = -1;
		try {
			br = new BufferedReader(new FileReader(args[1]));
			while ((line = br.readLine()) != null) {
				index = line.indexOf("=");
				if(index != -1)
					varType = line.substring(0,index);
				else
					varType = "";
				if(varType.equals("from_host")) {
					i = i + 1;
					varType = varType + i;
				}
				else if(varType.equals("to_host")) {
					j = j + 1;
					varType = varType + j;
				}	
				
				content = line.substring(index+1);
				switch(varType) {
					case "host" : 
						hostIP = content;
						break;
					case "name"	: 
						name = content;
						break;
					case "type" : 
						type = content;
						break;
					case "proto" : 
						proto = content;
						break;
					case "host_port" : 
						host_port = content;
						break;
					case "attacker_port" : 
						if(!content.equals("any"))
							attacker_port = content;
						break;
					case "attacker" : 
						attackerIP = content;
						break;
					case "from_host0" : 
						fromHost = content;
						break;
					case "to_host0" : 
						toHost = content;
						break;
					case "from_host1" : 
						fromHost1 = content;
						break;
					case "to_host1" : 
						toHost1 = content;
						break;
					case "from_host2" : 
						fromHost2 = content;
						break;
				}
			}
		}
	
		catch (IOException e) {
			e.printStackTrace();
		}
	
		final StringBuilder errbuf = new StringBuilder(); // For any error msgs
		final String file = args[0];
		Pcap pcap = Pcap.openOffline(file, errbuf);
		if (pcap == null) {
			System.err.printf("Error while opening device for capture: " + errbuf.toString());
			return;
		}
	
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			public void nextPacket(PcapPacket packet, String user) {
				packetslist.add(packet);
				if(type.trim().equals("stateless")){
					String tsrc = null, tdst = null;
					String usrc = null, udst = null;
					String ips = null, ipd = null;
					Tcp tcp = new Tcp();
					Udp udp = new Udp();
					Ip4 ip = new Ip4();
					String payload;
					StringBuilder str = new StringBuilder();
					packet.getUTF8String(0, str, packet.getTotalSize());
					String data = str.toString();
					payload = data;
					statefulstr1+=data;
					Payload p = new Payload();
				
					if(packet.hasHeader(p)) {
						packet.getHeader(p);
						byte[] payloadContent = p.getByteArray(0, p.size());
						String strPayloadContent = new String(payloadContent);
						statefulstr+=strPayloadContent ;
					}
				
					if(packet.hasHeader(Tcp.ID)) {
						packet.getHeader(tcp);
						tsrc = tcp.source()+"";
						tdst = tcp.destination()+"";
					}
	        
					if(packet.hasHeader(Ip4.ID)) {
						packet.getHeader(ip);
						ips = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
						ipd = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());
					}
	        
					if(packet.hasHeader(Udp.ID)) {
						packet.getHeader(udp);
						usrc = udp.source()+"";
						udst = udp.destination()+"";
					}
			
					if(name.trim().equals("Blame Attack 1")) {
						if(payload.contains("Now I own your computer")&&tdst.trim().equals(host_port.trim())&&ipd.trim().equals(hostIP.trim())) {
							System.out.println(name+" detected");
						}
					}
			
					if(name.trim().equals("Plaintext POP")) {
						String sr = null;
					
						if (!flag1) {
							sr = "\\+OK.*\\r\\n";
           	 			}
						else if ( !flag2) {
							sr = "USER .*\\r\\n" ;
           		 		}
						else if ( !flag3) {
							sr = "\\+OK.*\\r\\n" ;
						}
						else if ( !flag4) {
							sr = "PASS.*\r\n" ;
						}
						else if ( !flag5) {
							sr = "\\+OK.*\\r\\n" ;
						}
           	 
						Boolean contains = false;
					
						if(sr != null)
							contains = Match(sr,payload);
           
						if (contains && !flag1 && hostIP.trim().equals(ips)  && tsrc.equals(host_port.trim())) {
							flag1 = true;
           		  		}
						else if (contains &&  flag1 && !flag2 && hostIP.trim().equals(ipd)  && tdst.equals(host_port.trim())) {
							flag2 = true;
           		 		}
						else if (contains &&  flag1 && !flag3 && hostIP.trim().equals(ips)  && tsrc.equals(host_port.trim())) {
							flag3 = true;
						}
						else if (contains &&  flag1 && !flag4 && hostIP.trim().equals(ipd)  && tdst.equals(host_port.trim())) {
							flag4 = true;
           		  		}
						else if (contains &&  flag1 &&  flag2 &&  flag3 &&  flag4 &&  !flag5 && hostIP.trim().equals(ips)  && tsrc.equals(host_port.trim())) {
							flag5 = true;
							System.out.println(name + " detected");
						}
					}
			
					if(name.trim().equals("TFTP attacker boot")) {
						if(udp != null)
							if(Match("vmlinuz",payload)) {
								if(attacker_port.trim().equals(udst.trim())&&hostIP.trim().equals(ips.trim())) {
									flag1 = true;
								}
							}
				
						if(udp != null)
							if(Match("\\x00\\x03\\x00\\x01",payload)) {		
								if(attacker_port.trim().equals(usrc.trim())&&hostIP.trim().equals(ipd)) {
									flag2 = true;
								}
							}
						
						if(flag1 && flag2 && printc != 1) {
							printc = 1;
							System.out.println(name + " detected");
						}
					}
				}
			}
		};
	
		try {
			pcap.loop(-1, jpacketHandler, null);
		} 
	
		finally {
			pcap.close();
		}
	
		String ips = null, ipd = null;
		Ip4 ip1 = new Ip4();
	
		if(type.trim().equals("stateful")) {
			for(int i1=0; i1<packetslist.size()-1; i1++) {
				if(packetslist.get(i1).hasHeader(Ip4.ID)) {
					packetslist.get(i1).getHeader(ip1);
					ips = org.jnetpcap.packet.format.FormatUtils.ip(ip1.source());
					ipd = org.jnetpcap.packet.format.FormatUtils.ip(ip1.destination());
				}
			
				if(ips.equals(hostIP.trim())||ipd.equals(hostIP.trim())) {
					StringBuilder str = new StringBuilder();
					packetslist.get(i1).getUTF8String(0, str, packetslist.get(i1).getTotalSize());
					String data = str.toString();
					statefulstr1+=data;
					Payload p=new Payload();
					if(packetslist.get(i1).hasHeader(p)) {
						packetslist.get(i1).getHeader(p);
						byte[] payloadContent = p.getByteArray(0, p.size());
						String strPayloadContent = new String(payloadContent);
						statefulstr+=strPayloadContent ;
					}
				}
			}
	
			if(name.trim().equals("Blame Attack 2")) {
				if(statefulstr!=null)
					if(statefulstr.contains("Now I own your computer")) {
						System.out.println(name + " detected");
						statefulstr = null;
					}
			}
	
			if(name.trim().equals("Buffer Overflow")) {
				Boolean x90Flag = false;
				Boolean x80Flag = false;
				if(statefulstr1 != null){
					x90Flag = Match("\\x90.*{10}.*\\xcd",statefulstr1);
					x80Flag = Match("\\xcd\\x80",statefulstr1);
				}
	    
				if(x90Flag&&x80Flag) {
					System.out.println(name + " detected");
					statefulstr1 = null;
				}
			}
		}
	}

	protected static Boolean Match(String pattren, String stateless2) {
		Pattern pt1 = Pattern.compile(pattren, Pattern.MULTILINE);
		Matcher m1 = pt1.matcher(stateless2);
		return m1.find();
	}
}
