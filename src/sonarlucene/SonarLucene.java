package sonarlucene;

import java.io.File;
import java.nio.file.Paths;
import java.nio.file.Path;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.queryparser.classic.MultiFieldQueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.SimpleFSDirectory;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.document.TextField;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.zip.GZIPInputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.SequenceInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import org.apache.lucene.store.LockFactory;


/**
 *
 * @author breens
 */
public class SonarLucene {
 
    private static InputStream getDnsYielder(String sonarDir) throws Exception{
        File files = new File(sonarDir);
        String[] dnsAll = files.list( (File dirToFilter, String filename) -> filename.matches(".*_dnsrecords_all.gz") );
        File dnsAllFile = new File(sonarDir+File.separator+dnsAll[0]);
        return new GZIPInputStream(new FileInputStream(dnsAllFile));
    }
    
    private static InputStream getRevDnsYielder(String sonarDir) throws Exception {
        File files = new File(sonarDir);
        String[] revDns = files.list( (File dirToFilter, String filename) -> filename.matches(".*-rdns.gz") );
        File revDnsFile = new File(sonarDir+File.separator+revDns[0]);
        return new GZIPInputStream(new FileInputStream(revDnsFile));       
    }

    private static HashMap<String,ArrayList<String>> getSSLYielder(String sonarDir) throws Exception {
        //Setup the input streams to read all of the hosts and names files together
        File files = new File(sonarDir);
        String[] sslNamesList = files.list( (File dirToFilter, String filename) -> filename.matches(".*_names.gz") );
        String[] sslHostsList = files.list( (File dirToFilter, String filename) -> filename.matches(".*_((hosts)|(endpoints)).gz") );
        
        ArrayList<GZIPInputStream> sslNamesFis = new ArrayList<GZIPInputStream>();
        for(int i=0;i<sslNamesList.length;i++){
            sslNamesFis.add( new GZIPInputStream(new FileInputStream(new File(sonarDir+File.separator+sslNamesList[i]))));
        }
        SequenceInputStream sslNamesSis = new SequenceInputStream(Collections.enumeration(sslNamesFis));
        
        ArrayList<GZIPInputStream> sslHostsFis = new ArrayList<GZIPInputStream>();
        for(int i=0;i<sslHostsList.length;i++){
            sslHostsFis.add( new GZIPInputStream(new FileInputStream(new File(sonarDir+File.separator+sslHostsList[i]))));
        }
        SequenceInputStream sslHostsSis = new SequenceInputStream(Collections.enumeration(sslHostsFis));
        
        //Index the names into a hashmap in memory
        HashMap<String,String> namesToFingerprintMap = new HashMap<String,String>();
        Scanner sslNamesScanner = new Scanner(sslNamesSis);
        sslNamesScanner.useDelimiter("\n");
        String line;
        String[] hostFingerprint;
        while(sslNamesScanner.hasNext())
        {
            line = sslNamesScanner.next();
            hostFingerprint = line.split(","); //format is fingerprint,hostname
            if(hostFingerprint.length == 2){
                namesToFingerprintMap.put(hostFingerprint[0],hostFingerprint[1]);
            }
        }
        
        sslNamesScanner.close();
        Scanner sslHostsScanner = new Scanner(sslHostsSis).useDelimiter("\n");        
        
        String hostnameResult;
        HashMap<String,ArrayList<String>> hostnameToIPMap = new HashMap<String,ArrayList<String>>();
        ArrayList<String> hostIps;
        while(sslHostsScanner.hasNext())
        {
            line = sslHostsScanner.next();
            hostFingerprint = line.split(",");
            //Get last item in the string will always be the fingerprint, first will be ip address
            hostnameResult = namesToFingerprintMap.get(hostFingerprint[hostFingerprint.length-1]);
            if(hostnameResult != null){
                hostIps = hostnameToIPMap.putIfAbsent(hostnameResult,new ArrayList<String>(Arrays.asList(new String[] {hostFingerprint[0]})));
                //putIfAbsent returns null if item didnt already exist. if it did, returns the current list
                if(hostIps != null){
                    hostIps.add(hostnameResult);
                } 
            }
        }
        sslHostsScanner.close();
        return hostnameToIPMap;
    }
    
    private static int indexDnsAll(Scanner dnsYielder,IndexWriter iWriter) throws Exception{
        int count = 0;
        String domainName,line;
        String data;
        while(dnsYielder.hasNext()) {
           Document doc = new Document();
           line = dnsYielder.next();
           int split = line.indexOf((int)',');
           domainName = line.substring(0,split);
           data = line.substring(split+1,line.length());

           doc.add(new Field("hostname", domainName,TextField.TYPE_STORED));
           doc.add(new Field("dns_data", data,TextField.TYPE_STORED));
           //System.out.println(domainName);
           //System.out.println(data);
           //Adding doc to iWriter
           iWriter.addDocument(doc);
           count++;
        } 
        return count;
    }
    
    private static int indexRevDns(Scanner revDnsYielder,IndexWriter iWriter) throws Exception{
        int count = 0;
        String ipAddress,domainName;
        String line;
        while(revDnsYielder.hasNext()) {
           Document doc = new Document();
           line = revDnsYielder.next();
           int split = line.indexOf((int)',');
           ipAddress = line.substring(0,split);
           domainName = line.substring(split+1,line.length());

           doc.add(new Field("hostname", domainName,TextField.TYPE_STORED));
           doc.add(new Field("dns_data", ipAddress,TextField.TYPE_STORED));
           //System.out.println(domainName);
           //System.out.println(ipAddress);
           //Adding doc to iWriter
           iWriter.addDocument(doc);
           count++;
        } 
        return count;
    }
    
    private static int indexSSL(HashMap<String,ArrayList<String>> sslYielder,IndexWriter iWriter) throws Exception{
        int count=0;
        Iterator it = sslYielder.entrySet().iterator();
        String hostname;
        String ipList;
        List<String> ips;
        while(it.hasNext()){
            Map.Entry<String,List<String>> pair = (Map.Entry<String,List<String>>)it.next();
            hostname = pair.getKey();
            ips = pair.getValue();  
            ipList = String.join(",",ips);
            
            Document doc = new Document();
            doc.add(new Field("hostname", hostname,TextField.TYPE_STORED));
            doc.add(new Field("dns_data", ipList,TextField.TYPE_STORED));
            iWriter.addDocument(doc);
            count++;
            
        }
        return count;
    }
    
    public static void createIndex(boolean dnsAll, boolean revDns, boolean ssl,String indexPath,String sonarDataPath) throws Exception { 
        Path indexDirectory = Paths.get(indexPath);
        Path sonarData = Paths.get(sonarDataPath);
        System.out.println("-- Indexing --");

        try {
            
            //Create SequenceInputStreams for the varios sonar data files
            Scanner dnsYielder=null,revDnsYielder=null;
            HashMap<String,ArrayList<String>> sslYielder=null;
            if(dnsAll){
                dnsYielder = new Scanner(getDnsYielder(sonarDataPath)).useDelimiter("\n");
            }
            if(revDns){
                revDnsYielder = new Scanner(getRevDnsYielder(sonarDataPath)).useDelimiter("\n");
            }
            if(ssl)
            {
                sslYielder = getSSLYielder(sonarDataPath);
            }
            
            //Lucene Section
            Directory directory = new SimpleFSDirectory(indexDirectory);
            Analyzer analyzer = new HostnameIPAnalyzer();
            IndexWriterConfig conf = new IndexWriterConfig(analyzer);
            IndexWriter iWriter = new IndexWriter(directory, conf);

            int count=0;
            //Index each of the data files
            if(dnsAll){
                System.out.println("Indexing DNS all");
                count = indexDnsAll(dnsYielder,iWriter);
                System.out.println(count+" records indexed");                
            }

            if(revDns){
                System.out.println("Indexing Reverse DNS");
                count = indexRevDns(revDnsYielder,iWriter);
                System.out.println(count+" records indexed");
            }

            if(ssl)
            {
                System.out.println("Indexing SSL Data");
                count = count + indexSSL(sslYielder,iWriter);
                System.out.println(count+" records indexed");
            }

            //Close streams
            if(dnsAll) dnsYielder.close();
            if (revDns) revDnsYielder.close();
            //Closing iWriter
            iWriter.commit();
            iWriter.close();

        } 
        catch (Exception e) 
        {
            e.printStackTrace();
            throw e;
        }

     }
    public static void search(String keyword, String indexDir){
        search(keyword,indexDir,Integer.MAX_VALUE);
        
    }
     public static void search(String keyword, String indexDir, int maxResults) {
        try 
        {  
            Path indexPath = Paths.get(indexDir);
            //Searching
            IndexReader reader = DirectoryReader.open(FSDirectory.open(indexPath));
            IndexSearcher searcher = new IndexSearcher(reader);
            Analyzer analyzer = new HostnameIPAnalyzer();
            //MultiFieldQueryParser is used to search multiple fields
            String[] fieldsToSearch = {"hostname","dns_data"};
            MultiFieldQueryParser mqp = new MultiFieldQueryParser(fieldsToSearch , analyzer);

            System.out.println("Searching "+keyword);
            Query query = mqp.parse(keyword);//search the given keyword

            TopDocs hits = searcher.search(query, maxResults); // run the query

            for (int i = 0; i < hits.totalHits; i++)
            {
               Document doc = searcher.doc(hits.scoreDocs[i].doc);//get the next    document
               System.out.println(doc.get("hostname")+" "+doc.get("dns_data"));
            }

        } 
        catch (Exception e)
        {
            e.printStackTrace();
        }

     }
     
     private static void startFifoService(String inputFifo, String outputFifo, String indexDir) throws Exception{
        FileInputStream inputFifoFis = new FileInputStream(new File(inputFifo));
        FileOutputStream outputFos = new FileOutputStream(new File(outputFifo));
        PrintWriter outputFifoPw = new PrintWriter(outputFos);
        
        Scanner inputFifoScanner = new Scanner(inputFifoFis);

        Path indexPath = Paths.get(indexDir);
        //Searching
        IndexReader reader = DirectoryReader.open(FSDirectory.open(indexPath));
        IndexSearcher searcher = new IndexSearcher(reader);
        Analyzer analyzer = new HostnameIPAnalyzer();
        //MultiFieldQueryParser is used to search multiple fields
        String[] fieldsToSearch = {"hostname","dns_data"};
        MultiFieldQueryParser mqp = new MultiFieldQueryParser(fieldsToSearch , analyzer);
        TopDocs hits;
        Query query;
        String searchTerm = null;
        Document doc;
        while(true){
            searchTerm = inputFifoScanner.nextLine();
            query = mqp.parse(searchTerm);//search the given keyword

            hits = searcher.search(query, 300000); // run the query

            for (int i = 0; i < hits.totalHits; i++)
            {
               doc = searcher.doc(hits.scoreDocs[i].doc);//get the next    document
               outputFifoPw.println(doc.get("hostname")+" "+doc.get("dns_data"));
            }
            outputFifoPw.println("<<END OF RESULTS>>");
            outputFifoPw.flush();
        }
     }
     
     private static void printHelp(){
        System.out.println("Usage: java -jar SonarLucene.jar [-start_fifo_service </path/to/input_fifo> </path/to/output_fifo> </path/to/index_directory>] [-index <dnsall,revdns,ssl> </path/to/index_directory> </path/to/sonar_data>] [-search <query> </path/to/index_directory> <max results>]");
     }
     public static void main(String[] args)  throws Exception  {
        
        if(args.length == 0){
            printHelp();
            System.exit(0);
        }
        try{
            if(args[0].equals("-index")){
                boolean dnsAll=false,revDns=false,ssl=false;
                String pathToIndex = null,pathToSonar = null;
                String[] indexTypes = args[1].split(",");
                for (String indexType:indexTypes){
                    if(indexType.equals("dnsall") || indexType.equals("all")) dnsAll = true;
                    if(indexType.equals("revdns") || indexType.equals("all")) revDns = true;
                    if(indexType.equals("ssl") || indexType.equals("all")) ssl = true;

                }
                pathToIndex = args[2];
                pathToSonar = args[3];
                if(!dnsAll && !revDns && !ssl){
                    printHelp();
                    System.exit(0);
                }
                else
                {
                    createIndex(dnsAll,revDns,ssl,pathToIndex,pathToSonar);
                }
            }
            else if(args[0].equals("-search"))
            {
                int maxResults = Integer.MAX_VALUE;
                if(args.length == 4){
                    maxResults = Integer.parseInt(args[3]);
                }
                search(args[1],args[2],maxResults);    
            }
            else if(args[0].equals("-start_fifo_service")){
                //FileInputStream inputFifoFis = new FileInputStream(new File("/tmp/searchInput"));
                //System.out.println(inputFifoFis.read());
                //FileOutputStream outputFifoFos = new FileOutputStream(new File("/tmp/searchOutput"));
                //outputFifoFos.write(12);
                startFifoService(args[1],args[2],args[3]);
            }
            else{
                printHelp();
                System.exit(0);
            }

        }
        catch(Exception e){
            e.printStackTrace();
        }
     }

}
