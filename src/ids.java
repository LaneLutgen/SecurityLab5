
public class ids {
	
	public static void main(String[] args)
	{
		//Check that both files have been supplied
		if(args.length == 2)
		{
			
		}
		else
		{
			System.err.println("Please provided the policy file and the pcap trace file");
			System.err.println("Ex. java ids <policy-file> <pcap file>");
		}
	}
}
