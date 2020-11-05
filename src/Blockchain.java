/*--------------------------------------------------------

1. Name / Date: Riddhi Damani / 11-04-2020

2. Java version used, if not the official version for the class:
java version "9.0.4"
Java(TM) SE Runtime Environment (build 9.0.4+11)
Java HotSpot(TM) 64-Bit Server VM (build 9.0.4+11, mixed mode)

3. Precise command-line compilation examples / instructions:
In separate terminal windows:
Compilation Steps:
> javac -cp "gson-2.8.6.jar" Blockchain.java

4. Precise examples / instructions to run this program:
In separate terminal windows:
Execution Steps:
> java cp ".:gson-2.8.6.jar" Blockchain 0
> java cp ".:gson-2.8.6.jar" Blockchain 1
> java cp ".:gson-2.8.6.jar" Blockchain 2

5. List of files needed for running the program.
 a. checklist-block.html
 b. Blockchain.java
 c. BlockchainLog.txt
 d. BlockchainLedgerSample.json
 e. BlockInput0.txt, BlockInput1.txt, BlockInput2.txt


6. Notes:
Below process has been followed to create the blockchain:
a. Process 2 sends a message (start signal) to other processes - 0 and 1. Sleep() statements are inserted to aid in proper
   process coordination of all the 3 processes.
b. Once, each of the 3 processes receives the start signal, it will continue processing the other methods in the flow:
    - multicast of public keys (reading keys of each processes)
    - creating a dummy block for each process which will serve as the first block in the blockchain (process 0 creates it and
        multicast to other processes so that all processes start with the same initial block)
    - after all public keys are established, reading the input files - BlockInput0.txt, BlockInput1.txt, BlockInput2.txt
    - creating unverified blocks from its .txt file
    - multicasting the UVB to all the processes - processes in turn adds them to its priority queue
    - solving the work/puzzle - verification of the blocks
    - Adding to the blockchain ledger
c. Each process keeps a copy of the blockchain ledger that they access to add only when they receive the verified block.
d. Even if the block is not new i.e. it has been updated, it will always be added to the blockchain if it doesn't exist there.
e. I have implemented this blockchain - by sending the verified block to all other processes and adding it to the blockchain.
f. Few additional console commands have been implemented too:- C (Credit), V (Verify Entire Blockchain), L (list of records on
    single line). I was unable to implement the R (Reading file of records to create new data!).


7. Web Sources Credits - THANKS!
https://medium.com/programmers-blockchain/create-simple-blockchain-java-tutorial-from-scratch-6eeed3cb03fa
https://www.quickprogrammingtips.com/java/how-to-generate-sha256-hash-in-java.html
https://mkyong.com/java/how-to-parse-json-with-gson/
http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
https://www.mkyong.com/java/java-sha-hashing-example/
https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html

----------------------------------------------------------*/
// Importing the gson libraries to convert JSON to Java objects and vice-versa

import com.google.gson.Gson;
// Importing the gson builder library to construct the Gson object
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
// Importing the java input-output libraries
import java.io.*;
// Importing the network server socket libraries
import java.lang.reflect.Type;
import java.net.ServerSocket;
// Importing the java socket libraries
import java.net.Socket;
// Importing the java constant charset libraries for UTF-8
import java.nio.charset.StandardCharsets;
// Importing the java security libraries
import java.security.*;
// Importing the java security library for providing encoding to public key
import java.security.spec.X509EncodedKeySpec;
// Importing the java utility libraries
import java.util.*;
// Importing the java blocking queue libraries
import java.util.concurrent.BlockingQueue;
// Importing the java priority blocking queue libraries
import java.util.concurrent.PriorityBlockingQueue;

// Main Blockchain class
public class Blockchain {
    // main() method for blockchain class
    public static void main(String[] args) {
        // int queueLength = 6;
        // declaring processID variable
        int processID;
        // Based on the argument passed in the console - process 0, 1 or 2
        // we trigger the 3 different processes from Blockchain.java
        switch (args[0]) {
            // Checking whether the argument pass is 0; assigns '0' to processID for further processing
            case "0":
                processID = 0;
                break;
            // Checking whether the argument pass is 1; assigns '1' to processID for further processing
            case "1":
                processID = 1;
                break;
            // Checking whether the argument pass is 2; assigns '2' to processID for further processing
            case "2":
                processID = 2;
                break;
            // If no argument is passed, then it triggers the process 0 as default
            default:
                processID = 0;
                break;
        }
        // Passing the process ID to blockChainTaskToDo class where all task for the blockchain
        // will be performed. Doing this to keep the code clean by isolating the blockchain task with the main
        // functionality
        BlockChainTaskToDo bcTtd = new BlockChainTaskToDo(processID);
    }
}

// Block record class
class BlockRecord implements Serializable {
    // declaring block id variable - for having unique block ID
    // created during read-in of data record from file
    private String block_ID;
    // declaring signed block id variable
    private String signedBlock_ID;
    // declaring timeStamp variable
    private String timeStamp;
    // declaring block number variable
    private String blockNumber;
    // declaring first name variable of patient
    private String firstName;
    // declaring last name variable of patient
    private String lastName;
    // declaring date of birth variable of patient
    private String dateOfBirth;
    // declaring ssn number variable of patient
    private String ssnNumber;
    // declaring medical diagnosis variable of patient
    private String medDiag;
    // declaring medical treatment variable of patient
    private String medTreat;
    // declaring medical prescription (Rx) variable of patient
    private String medRX;
    // declaring hash creator variable
    private String hashMaker;
    // declaring hash signed creator variable
    private String hashSignedMaker;
    // declaring previous hash variable
    // Used to store winning hash value of previous block
    private String previousHashValue;
    // declaring winning hash variable
    private String winningHashValue;
    // declaring winning signed hash variable
    private String winningSignedHashValue;
    // declaring random seed variable
    private String randomSeedValue;
    // declaring process ID verification variable
    // Used to store processID that will verify the block for providing credit
    private String processIDVerification;
    // declaring process creation variable
    private String processCreation;
    // declaring uuid variable
    private UUID uuid;

    // ------- below are accessors for above variable declaration -----------
    // getter method for block id variable
    public String getBlock_ID() {
        return block_ID;
    }

    // setter method for block id variable
    public void setBlock_ID(String block_ID) {
        this.block_ID = block_ID;
    }

    // getter method for signed block id variable
    public String getSignedBlock_ID() {
        return signedBlock_ID;
    }

    // setter method for signed block id variable
    public void setSignedBlock_ID(String signedBlock_ID) {
        this.signedBlock_ID = signedBlock_ID;
    }

    // getter method for timestamp variable
    public String getTimeStamp() {
        return timeStamp;
    }

    // setter method for timestamp variable
    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }

    // getter method for block number variable
    public String getBlockNumber() {
        return blockNumber;
    }

    // setter method for block number variable
    public void setBlockNumber(String blockNumber) {
        this.blockNumber = blockNumber;
    }

    // getter method for first name variable
    public String getFirstName() {
        return firstName;
    }

    // setter method for first name variable
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    // getter method for last name variable
    public String getLastName() {
        return lastName;
    }

    // setter method for last name variable
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    // getter method for date for birth variable
    public String getDateOfBirth() {
        return dateOfBirth;
    }

    // setter method for date for birth variable
    public void setDateOfBirth(String dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    // getter method for ssn number variable
    public String getSsnNumber() {
        return ssnNumber;
    }

    // setter method for ssn number variable
    public void setSsnNumber(String ssnNumber) {
        this.ssnNumber = ssnNumber;
    }

    // getter method for medical diagnosis variable
    public String getMedDiag() {
        return medDiag;
    }

    // setter method for medical diagnosis variable
    public void setMedDiag(String medDiag) {
        this.medDiag = medDiag;
    }

    // getter method for treatment variable
    public String getMedTreat() {
        return medTreat;
    }

    // setter method for treatment variable
    public void setMedTreat(String medTreat) {
        this.medTreat = medTreat;
    }

    // getter method for medical prescription(Rx) variable
    public String getMedRX() {
        return medRX;
    }

    // setter method for medical prescription(Rx) variable
    public void setMedRX(String medRX) {
        this.medRX = medRX;
    }

    // getter method for hash maker  variable
    public String getHashMaker() {
        return hashMaker;
    }

    // setter method for hash maker variable
    public void setHashMaker(String hashMaker) {
        this.hashMaker = hashMaker;
    }

    // getter method for hash signed maker variable
    // Used to store signed hash value after the process has solved the 'Work' puzzle
    public String getHashSignedMaker() {
        return hashSignedMaker;
    }

    // setter method for hash signed maker variable
    public void setHashSignedMaker(String hashSignedMaker) {
        this.hashSignedMaker = hashSignedMaker;
    }

    // getter method for previous hash value variable
    public String getPreviousHashValue() {
        return previousHashValue;
    }

    // setter method for previous hash value variable
    public void setPreviousHashValue(String previousHashValue) {
        this.previousHashValue = previousHashValue;
    }

    // getter method for winning hash value variable
    public String getWinningHashValue() {
        return winningHashValue;
    }

    // setter method for winning hash value variable
    public void setWinningHashValue(String winningHashValue) {
        this.winningHashValue = winningHashValue;
    }

    // getter method for winning signed hash value variable
    public String getWinningSignedHashValue() {
        return winningSignedHashValue;
    }

    // setter method for winning signed hash value variable
    public void setWinningSignedHashValue(String winningSignedHashValue) {
        this.winningSignedHashValue = winningSignedHashValue;
    }

    // getter method for random seed value variable
    public String getRandomSeedValue() {
        return randomSeedValue;
    }

    // setter method for random seed value variable
    public void setRandomSeedValue(String randomSeedValue) {
        this.randomSeedValue = randomSeedValue;
    }

    // getter method for process id verification variable
    public String getProcessIDVerification() {
        return processIDVerification;
    }

    // setter method for process id verification variable
    public void setProcessIDVerification(String processIDVerification) {
        this.processIDVerification = processIDVerification;
    }

    // getter method for process creation variable. For verification of the signature, we are required to know
    // which process's public key has been used has been used to create the block
    public String getProcessCreation() {
        return processCreation;
    }

    // setter method for process creation variable
    public void setProcessCreation(String processCreation) {
        this.processCreation = processCreation;
    }

    // getter method for UUID variable
    public UUID getUuid() {
        return uuid;
    }

    // setter method for UUID variable
    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    @Override
    public String toString() {
        return "BlockRecord{" +
                "block_ID='" + block_ID + '\'' +
                ", signedBlock_ID='" + signedBlock_ID + '\'' +
                ", timeStamp='" + timeStamp + '\'' +
                ", blockNumber='" + blockNumber + '\'' +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", dateOfBirth='" + dateOfBirth + '\'' +
                ", ssnNumber='" + ssnNumber + '\'' +
                ", medDiag='" + medDiag + '\'' +
                ", medTreat='" + medTreat + '\'' +
                ", medRX='" + medRX + '\'' +
                ", hashMaker='" + hashMaker + '\'' +
                ", hashSignedMaker='" + hashSignedMaker + '\'' +
                ", previousHashValue='" + previousHashValue + '\'' +
                ", winningHashValue='" + winningHashValue + '\'' +
                ", winningSignedHashValue='" + winningSignedHashValue + '\'' +
                ", randomSeedValue='" + randomSeedValue + '\'' +
                ", processIDVerification='" + processIDVerification + '\'' +
                ", processCreation='" + processCreation + '\'' +
                ", uuid=" + uuid +
                '}';
    }
}

// BlockChainTaskToDo class
class BlockChainTaskToDo {
    // locally declared process ID variable. stores current process id that will be
    // received from the Blockchain class
    public static int processID;
    // total number of processes that can be served.
    // Can update this number for handling any number of peers
    public static int totalNumProcesses = 3;
    // declaring and initializing server name variable
    public static String sName = "localhost";
    // a flag variable that indicates when all processes can start execution
    // once updated to 'true'. Initial value set to false.
    public static boolean beginProcessFlag = false;
    // declaring and initializing a public key flag variable
    public static boolean pkFlag = false;
    // declaring and initializing public key counter variable
    public static int pkCount = 0;
    //public static String blockchain = "[First block]";
    // used to store key pair for the processes
    public static KeyPair keysPair;
    // used to store our processes public keys - for 3 processes; it will store 3
    // public key in the array
    public static PublicKey[] publicKeyList = new PublicKey[totalNumProcesses];
    // declaring a priority blocking queue for storing unverified blocks (unmarshalled block into java object)
    // from here, each process will pick the block for solving puzzle
    public static final PriorityBlockingQueue<BlockRecord> blockQueue = new PriorityBlockingQueue<>(50, new BRComparator());
    // used to store our verified blocks - our Blockchain Ledger
    public static LinkedList<BlockRecord> bcLedger = new LinkedList<>();
    // used to store block records (i.e. unverified blocks) initially for our processes
    public static LinkedList<BlockRecord> brList = new LinkedList<>();

    // Token indexes for input file data //
    // first name index set to 0
    private static final int iFName = 0;
    // last name index set to 1
    private static final int iLName = 1;
    // date of birth index set to 2
    private static final int iDob = 2;
    // ssn number index set to 3
    private static final int iSsnNum = 3;
    // medical diagnosis index set to 4
    private static final int iMedDiag = 4;
    // medical treatment index set to 5
    private static final int iMedTreatment = 5;
    // medical prescription index set to 6
    private static final int iMedRx = 6;

    // constructor class that assigns process id to local variable and
    // initiates and sets all ports for the specific process and executes
    // the run method
    public BlockChainTaskToDo(int processID) {
        BlockChainTaskToDo.processID = processID;
        // instantiating Ports class and setting the ports for each process ID
        new Ports().setPorts(processID);
        // Invoking the run() method for further processing
        run();
    }

    // run() method
    public void run() {
        // Display message for launching the BlockChain procedure
        System.out.println("Riddhi Damani's BlockChain in progress..\n");
        // Display message indicating process specific input file access
        System.out.println("Currently, utilizing input file: " + String.format("BlockInput%d.txt", processID));
        // new thread created for starting the main server - this will set the beginProcessFlag to TRUE
        new Thread(new StartMainServer()).start();
        // new thread created for receiving public keys for each process (including THIS process)
        // Process 0 - 4710, Process 1 - 4711, Process 2 - 4712
        new Thread(new PublicKeysServer()).start();
        // new thread created for receiving unverified blocks in the priority queue for each process (including THIS process)
        // Process 0 - 4820, Process 1 - 4821, Process 2 - 4822
        new Thread(new UVBlockServer(blockQueue)).start();
        // new thread created for receiving updated blocks (then, adding this block in the ledger)
        // from all processes (including THIS process)
        // Process 0 - 4930, Process 1 - 4931, Process 2 - 4932
        new Thread(new UBlockchainServer()).start();
        // Sleeping for ~2 seconds in order for all the processes to be active before
        // continuing the activities
        try {
            Thread.sleep(2000);
        } catch (Exception exception) {
            // exception handling
            exception.printStackTrace();
        }

        // if process id received is 2 - it will trigger all other processes
        // and send signal to start processing
        if (processID == 2) {
            // invokes startAllProcesses() method
            startAllProcesses();
        }

        // Generating keyPair and invoking generateKeyPair() method and passing in random seed value
        try {
            keysPair = generateKeyPair(999);
        } catch (Exception exception) {
            // exception handling
            exception.printStackTrace();
        }

        // if beginProcessFlag is not true, waiting for all the processes to start, hence
        // calling sleep method
        while (!beginProcessFlag) {
            callSleep();
        }
        // display message
        System.out.println("Launching...");
        // Invoking the multicast method wherein each processes share their public keys
        // with each other
        multiCastPublicKeys();
        // if pkFlag is false; it will call the sleep method
        while (!pkFlag) {
            callSleep();
        }
        // if processID == 0 then invoke dummy entry (block)
        if (processID == 0) {
            createGenesisBlock();
        }
        // Invoking readInputFile() method - each process invokes its own readInputFile method
        readInputFile();
        // Invoking multiCast2Processes() method for multicasting/send unverified blocks to all processes (including
        // THIS process) for solving the work and get the block verified
        multiCast2Processes();

        // invoking sleep statement so all processes complete reading and multicasting
        // UVB before they start competing
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // created new thread for processes to solve the work puzzle
        new Thread(new WorkPuzzle(blockQueue)).start();

        try {
            Thread.sleep(21000);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        System.out.println("-------------------------------------------------------");
        System.out.println("BlockChain Ledger Successfully Created (in JSON format)!");
        System.out.println("-------------------------------------------------------");
        System.out.println("For further processing, please enter commands as below:");
        System.out.println("1. Enter 'C' for Credits");
        System.out.println("2. Enter 'V' for Verifying entire BlockChain again");
        System.out.println("3. Enter 'L' for List records in single line");
        System.out.println("-------------------------------------------------------");
        while (true) {
            System.out.println("\n");
            System.out.println("Please enter your preferred command :");
            Scanner consoleCmd = new Scanner(System.in);
            String command = consoleCmd.nextLine();
            System.out.println(command);
            switch (command) {
                case "C":
                case "c":
                    processCredits();
                    break;
                case "V":
                case "v":
                    verifyBlockChain();
                    break;
                case "L":
                case "l":
                    listBlockRecords();
                    break;
            }
        }
    }

    // Method invoked when user wish to list the verified blocks in the blockchain ledger
    // Invoked when user enters command 'L' or 'l' in the console.
    private void listBlockRecords() {
        Gson gson = new Gson();
        LinkedList<BlockRecord> listRecords;
        // Reading the blockchain ledger file
        try {
            Reader inputFile = new FileReader("BlockchainLedger.json");
            Type typeFormat = new TypeToken<LinkedList<BlockRecord>>() {
            }.getType();
            // creating list of records
            listRecords = gson.fromJson(inputFile, typeFormat);
            System.out.println("Below verified records are present in our BlockChain Ledger (latest first):");
            // Creating a iterator for listRecords
            Iterator<BlockRecord> it = listRecords.iterator();
            int count = listRecords.size();
            // Iterating the list and printing it on console in a single line
            while (it.hasNext()) {
                BlockRecord tempRec = it.next();
                System.out.printf("%d. " + "%s %s %s %s %s %s %s %s \n", count,
                        tempRec.getTimeStamp(), tempRec.getFirstName(),
                        tempRec.getLastName(), tempRec.getDateOfBirth(),
                        tempRec.getSsnNumber(), tempRec.getMedDiag(),
                        tempRec.getMedTreat(), tempRec.getMedRX());
                count--;
            }
        } catch (IOException ioException) {
            // Exception Handling
            ioException.printStackTrace();
        }
    }

    // Method that verifies the entire blockchain ledger in simple format.
    // It is invoked when user enters command 'V' or 'v' in the console.
    private void verifyBlockChain() {
        boolean flag = false;
        Gson gson = new Gson();
        LinkedList<BlockRecord> listRecords;
        try {
            // Reading the ledger
            Reader inputFile = new FileReader("BlockchainLedger.json");
            Type typeFormat = new TypeToken<LinkedList<BlockRecord>>() {}.getType();
            // Storing the records in the ledger in the temporary LinkedList
            listRecords = gson.fromJson(inputFile, typeFormat);

            // Looping through the listRecords
            for (BlockRecord rec : listRecords) {
                String recNum = rec.getBlockNumber();
                // Skipping the dummy block record
                if(!recNum.equals("1"))
                {
                    //System.out.println("Block Number: " + recNum);
                    String dataStr;
                    // Taking the block record in the string format
                    String blockRecord = rec.getBlock_ID() +
                            rec.getFirstName() + rec.getLastName() + rec.getSsnNumber() +
                            rec.getDateOfBirth() + rec.getMedDiag() +
                            rec.getMedTreat() + rec.getMedRX() + rec.getProcessCreation();
                    try {
                        // Concatenating block data, previous block hash value and random seed
                        // adding blockRecord to UBlock
                        String UBlock = blockRecord;
                        // adding the previous Hash Value
                        UBlock = UBlock + rec.getPreviousHashValue();
                        // adding random seed value
                        String concatData = UBlock + rec.getRandomSeedValue();

                        // Producing new SHA-256 hash of our concatenated block
                        MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");
                        byte[] hashValueBytes = msgDigest.digest(concatData.getBytes(StandardCharsets.UTF_8));
                        // converting of bytes to string of hexadecimal values
                        dataStr = WorkPuzzle.byteArray2Str(hashValueBytes);

                        //  Verifying whether the SHA-256 hash value in the current block's header
                        //  matches the new hash value
                        if (!dataStr.equals(rec.getWinningHashValue())) {
                            System.out.println("Verification for hash (SHA-256) failed.\n");
                            flag = true;
                        }

                        // Between 0000 (0) and FFFF (65535). Getting numeric value of 1st 16 bits,
                        int workNum = Integer.parseInt(dataStr.substring(0, 4), 16);

                        // Checking to make sure workNum does not exceed threshold
                        // Verifying that the hash just created solves the puzzle
                        if (!(workNum < 20000)) {
                            System.out.println("Work Puzzle was not solved\n");
                            flag = true;
                        }

                        try {
                            // Validating the signed - sha 256 signature by utilizing the public key of the process
                            // that verified it.
                            boolean hashVerified = verifySignature(rec.getWinningHashValue().getBytes(),
                                    publicKeyList[Integer.parseInt(rec.getProcessIDVerification())],
                                    Base64.getDecoder().decode(rec.getWinningSignedHashValue()));
                            // Based on hash verification, display message accordingly
                            if(hashVerified) {
                                System.out.println("#BlockID: " + recNum + " Hash (SHA-256) signature verified successfully");
                            }
                            else {
                                System.out.println("#BlockID: " + recNum + " Hash (SHA-256) signature verification failed!");
                                flag = true;
                            }

                            // Validating the signed block ID by utilizing the public key of the process
                            // that created it.
                            boolean blockIDVerified = verifySignature(rec.getBlock_ID().getBytes(),
                                    publicKeyList[Integer.parseInt(rec.getProcessCreation())],
                                    Base64.getDecoder().decode(rec.getSignedBlock_ID()));

                            // Based on Block ID signature verification, display message accordingly
                            if(blockIDVerified) {
                                System.out.println("#BlockID: " + recNum + " Signature verified successfully");
                            }
                            else {
                                System.out.println("#BlockID: " + recNum + " Signature verification failed!");
                                flag = true;
                            }
                        } catch (Exception exception) {
                            // Exception handling
                            exception.printStackTrace();
                        }
                    } catch (NoSuchAlgorithmException exception) {
                        // Exception handling
                        exception.printStackTrace();
                    }
                }
            }
        }
        catch (Exception exception) {
            // Exception handling
            exception.printStackTrace();
        }

        // Display message when entire blockchain gets verified
        String message = (!flag) ? "Entire Blockchain Verification SUCCESSFULLY COMPLETED!" : "Errors in the" +
                "ledger exists!";
        System.out.println(message);
    }

    // Method that iterates through the blockchain ledger, keeps a tally of which process verified which block
    // and displays the final count on the console.
    // Method invoked when user enters command 'C' or 'c' in the console.
    private void processCredits() {
        Gson gson = new Gson();
        LinkedList<BlockRecord> listRecords;
        // declaring array variable for store the credit score for each process
        int[] creditScore = new int[totalNumProcesses];
        try {
            // Reading the ledger file
            Reader inputFile = new FileReader("BlockchainLedger.json");
            Type typeFormat = new TypeToken<LinkedList<BlockRecord>>() {}.getType();
            // writing the blocks into a temporary linked list - listRecords
            listRecords = gson.fromJson(inputFile, typeFormat);
            // looping through the list to count
            for (BlockRecord rec : listRecords) {
                if (rec.getProcessIDVerification() != null) {
                    // checking the process number that verified the block and incrementing the counter
                    // accordingly
                    int processNumber = Integer.parseInt(rec.getProcessIDVerification());
                    creditScore[processNumber]++;
                }
            }
            // Displaying the final credit count on the console
            System.out.println("Verification Credit received by Processes:");
            System.out.printf("Credit for P0: %d" + "\n" +
                            "Credit for P1: %d" + "\n" +
                            "Credit for P2: %d", creditScore[0],
                    creditScore[1], creditScore[2]);
        } catch (IOException ioException) {
            // exception handling
            ioException.printStackTrace();
        }
    }

    // Method to multicast unverified blocks to all the processes.
    // So, that each process can compete to verify the blocks by solving the puzzle
    public void multiCast2Processes() {
        // declaring the socket variable
        Socket mcpSocket;
        // declaring the printStream variable
        PrintStream send2Server;
        // declaring the tempBlockRec variable
        BlockRecord tempBlockRec;
        // declaring an iterator to loop through all the records in our unverified block linked list
        Iterator<BlockRecord> iteratorVar = brList.iterator();
        try {
            while (iteratorVar.hasNext()) {

                tempBlockRec = iteratorVar.next();
                // creating JSON format of block record
                String blockRec = jsonBuilder(tempBlockRec);
                for (int i = 0; i < totalNumProcesses; i++) {
                    // establishing connection for each processes on their unverified block server
                    mcpSocket = new Socket(sName, Ports.portBaseUBServer + i);
                    send2Server = new PrintStream(mcpSocket.getOutputStream());
                    // sending block record to each process
                    send2Server.println(blockRec);
                    // flushes print stream
                    send2Server.flush();
                    // closes socket connection
                    mcpSocket.close();
                }
            }
        } catch (Exception excpt) {
            // exception handling
            excpt.printStackTrace();
        }
    }

    // Method to make the thread sleep for sometime till all processes are on same page for execution
    public static void callSleep() {
        try {
            Thread.sleep(1000);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    // Method to check duplicate records in the blockchain ledger. If duplicate block exist,
    public static boolean isDuplicate(BlockRecord blockRecordIn) {
        // creating local variable to bind the block record passed in as an argument by calling function
        BlockRecord checkRec = blockRecordIn;
        // Parsing through our blockchain ledger
        for (BlockRecord blockRecord : bcLedger) {
            // checks our passed blockRec with every record already existing in ledger using block id field.
            // If, it matches then returns true
            if (checkRec.getBlock_ID().equals(blockRecord.getBlock_ID()))
                return true;
        }
        // else returns false
        return false;
    }

    // method to create a pair of key (i.e. Public key and a Private key)
    // It is a part of the utility code provided by professor Elliott
    public static KeyPair generateKeyPair(long randomSeed) throws Exception {
        // Creating a keyGenerator object to utilize Java's KeyPairGenerator class. Calling getInstance() method on it and
        // Passing the encryption algorithm "RSA" that will be used to generate the keys
        // In nutshell, generating 1024 bit key pair using Digital Signature (RSA) algorithm
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        // Creating a SecureRandom object and re-seeding it by setting random seed value
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(randomSeed);
        // Initializing the key size for our keyGenerator instance
        keyGenerator.initialize(1024, rng);
        // generates the key pair using the generateKeyPair() and
        // returns to the calling function
        return (keyGenerator.generateKeyPair());
    }

    // Multicast of public keys method - receives the public key and multicast/broadcasts the key to other
    // processes. There is an additional piece of data attached with the key i.e. process ID.
    // Doing this will aid in deciding which public key can be used when verifying the block
    public void multiCastPublicKeys() {
        // declaring mcpkSocket Socket variable
        Socket mcpkSocket;
        // declaring send2Server PrintStream variable
        PrintStream send2Server;
        // getting the bytes of public key of the keysPair variable
        byte[] publicKey = keysPair.getPublic().getEncoded();
        // converting byte[] digital signature into string format in order to place into our block
        String strPublicKey = Base64.getEncoder().encodeToString(publicKey);
        // displaying the public key string on the terminal
        System.out.println("Public Key Created for MultiCasting: " + strPublicKey);
        try {
            // looping through total number of processes
            for (int i = 0; i < totalNumProcesses; i++) {
                // creating socket object 'mcpkSocket' and passing in server name and public key server port number
                mcpkSocket = new Socket(sName, Ports.portBaseKeyServer + i);
                // creating printStream object and assigning output stream on the above socket for multicasting the keys
                send2Server = new PrintStream(mcpkSocket.getOutputStream());
                // concatenating process ID and public key str
                String pIDPublicKey = processID + " " + strPublicKey;
                // sending the public key to each servers/processes
                send2Server.println(pIDPublicKey);
                // flushing the printStream
                send2Server.flush();
                // closing the socket
                mcpkSocket.close();
            }
        } catch (Exception exception) {
            // exception handling
            exception.printStackTrace();
        }
    }

    // Method used by process 2 to send a "start" signal to all other processes.
    // Once the signal is received, they flip the flag beginProcessFlag and thus, continue the rest
    // of the operation/task
    public boolean startAllProcesses() {
        // declaring startSocket variable
        Socket startSocket;
        // declaring send2Server variable
        PrintStream send2Server;
        try {
            // looping through total number of processes
            for (int i = 0; i < totalNumProcesses; i++) {
                // initializing startSocket with localhost and startServer port base + process number
                startSocket = new Socket(sName, Ports.portBaseStartServer + i);
                // creating a new printStream object with startSocket and assigning it to send2Server
                send2Server = new PrintStream(startSocket.getOutputStream());
                // sending 'start' message
                send2Server.println("start");
                // Printing out display message on Process 2
                System.out.println("Sending Start Signal...");
                // flushes the output stream
                send2Server.flush();
                // closing the startSocket
                startSocket.close();
            }
        } catch (Exception exception) {
            // exception handling
            exception.printStackTrace();
        }
        // returns true for starting all processes
        return true;
    }

    // Method to create a dummy block that will be a basis (initial block - starting point) of all the processes
    // By setting the initial values we are ensuring that each block gets the common data
    public static void createGenesisBlock() {

        // declaring SHA256Data variable
        String SHA256Data;
        // creating BlockRecord type object
        BlockRecord blockRec = new BlockRecord();
        // creating a Date type object to store date value - fetches the system formatted date
        // Ex: Sun Nov 01 22:25:16 CST 2020
        Date dateValue = new Date();
        //System.out.println("DATE: " + dateValue);
        // declaring and initializing timeValue variable - fetches current time
        // Ex: 1604291116380
        long timeValue = dateValue.getTime();
        //System.out.println("TIME: " + timeValue);

        // converting time value into string format
        String strTimeValue = String.valueOf(timeValue);
        // creating a timestamp out of time value by appending the processID along with it.
        // this will aid in solving the issue of same timestamps of block records
        String timeStamped = strTimeValue + "." + processID;
        // generating random UUID's and assigning it to setUUID variable
        String setUUID = UUID.randomUUID().toString();

        // Setting initial values (default values) for all the fields of our block record
        blockRec.setBlock_ID(setUUID);
        blockRec.setTimeStamp(timeStamped);
        blockRec.setFirstName("George");
        blockRec.setLastName("Bushel");
        blockRec.setSsnNumber("111-00-1111");
        blockRec.setDateOfBirth("1890.10.10");
        blockRec.setMedDiag("Cancer");
        blockRec.setMedTreat("Chemotheraphy");
        blockRec.setMedRX("HealthyFood");
        blockRec.setPreviousHashValue("1111111111");
        blockRec.setBlockNumber("1");

        // Creating string format of our block record values that will aid in creating
        // SHA256 Hash value later
        String blockRecord = blockRec.getBlock_ID() +
                blockRec.getFirstName() +
                blockRec.getLastName() +
                blockRec.getSsnNumber() +
                blockRec.getDateOfBirth() +
                blockRec.getMedDiag() +
                blockRec.getMedTreat() +
                blockRec.getMedRX();

        // Invoking Message Digest functionality on our string block record by invoking MD2StringBuilder method
        SHA256Data = MD2StringBuilder(blockRecord);

        // setting the newly generated hash value of the block as winning hash value
        // for dummy record
        blockRec.setWinningHashValue(SHA256Data);

        // Adding the first dummy record to blockchain ledger at 0th index
        bcLedger.add(0, blockRec);
        // Displaying message on terminal stating the current size of ledger
        System.out.println("Size of the BlockChain Ledger is: " + bcLedger.size());

        // allowing dummy block record to be written on the blockchain ledger
        if (processID == 0) {
            // displaying message on the terminal on the action being performed
            System.out.println("Writing first block to BC ledger");
            // sending block to the ledger
            sendBlock2Ledger(blockRec, "bcLedgerUpdate");
            // writing JSON on the disk
            writeToJSON();
        }
    }

    // Method when invoked allows to send block to our blockchain ledger.
    // Based on operation type : bcLedgerUpdate or reVerifyBlock passed by the calling method - decision is made.
    // bcLedgerUpdate operation: if block is verified, and prepared to be inserted into our ledger, this operation is used.
    //                      This will also send an update to each processes on their updated blockchain server port.
    // reVerifyBlock: if block requires reverification, then it is diverted to the unverified block server port of each
    //               processes rather than adding to the blockchain ledger.
    public static void sendBlock2Ledger(BlockRecord blockRec, String operation) {
        // declaring socket variable
        Socket sblSocket;
        // declaring send2Server variable
        PrintStream send2Server;
        // switch functionality
        switch (operation) {
            case "bcLedgerUpdate":
                try {
                    // looping through total number of processes
                    for (int i = 0; i < totalNumProcesses; i++) {
                        // setting up updated blockchain server port socket for sending verified block
                        sblSocket = new Socket(sName, Ports.portBaseUpdatedBC + i);
                        // setting up printStream object in order to send the block to the server port
                        send2Server = new PrintStream(sblSocket.getOutputStream());
                        // marshalling record as JSON object using jsonBuilder method and then sending to the respective
                        // processes port
                        send2Server.println(jsonBuilder(blockRec));
                        // Displaying message on the terminal
                        System.out.println("Verified block is being broadcast " + blockRec.getBlock_ID());
                        // flushes the print stream
                        send2Server.flush();
                        // closes the socket connection
                        sblSocket.close();
                    }
                } catch (IOException ioException) {
                    // exception handling
                    ioException.printStackTrace();
                }
                break;
            case "reVerifyBlock":
                try {
                    // looping through total number of processes
                    for (int j = 0; j < totalNumProcesses; j++) {
                        // setting up unverified block server port socket for sending in blocks that needs to be re-verified
                        sblSocket = new Socket(sName, Ports.portBaseUBServer + j);
                        // setting up printStream object in order to send the block to the server port
                        send2Server = new PrintStream(sblSocket.getOutputStream());
                        // marshalling record as JSON object using jsonBuilder method and then sending to the respective
                        // processes port
                        send2Server.println(jsonBuilder(blockRec));
                        // Displaying message on the terminal
                        System.out.println("Block is being broadcast: " + blockRec.getBlock_ID());
                        // flushes the print stream
                        send2Server.flush();
                        // closes the socket connection
                        sblSocket.close();
                    }
                } catch (IOException ioException) {
                    // exception handling
                    ioException.printStackTrace();
                }
                break;
        }
    }

    // Method used to marshall java object to JSON using gson. Input to this method is the blockrec and is passed
    // toJson for conversion; return the json format output
    public static String jsonBuilder(BlockRecord blockRec) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(blockRec);
        return json;
    }

    // Method that reads in the 3 input files - BlockInput0.txt, BlockInput1.txt, BlockInput2.txt
    // Then, creates the token for each data value and utilizes it to create un-verified block.
    // This block will have a SHA256 hash string value that will aid in creating digital signature later for auditing
    // This will ensure that our block is digitally signed.
    public static void readInputFile() {
        // formatting of the input file based on respective process ID
        // Making it dynamic - inorder to input any number of peers BlockInput files
        String inputFile = String.format("BlockInput%d.txt", processID);
        try {
            // each process reads in its own input file in inputData variable
            BufferedReader inputData = new BufferedReader(new FileReader(inputFile));
            // creating tokens to place the input data as per the defined java variables for it
            String[] DTokens;
            // String that stores entire text input data
            String inputStrData;
            // declaring variable blockUUID to store the unique blockID
            String blockUUID;
            try {
                // if the inputData is not null
                while ((inputStrData = inputData.readLine()) != null) {
                    // creating date instance
                    Date dateValue = new Date();
                    // creating block record instance
                    BlockRecord blockRec = new BlockRecord();
                    // declaring and initializing timeValue variable - fetches current time
                    long timeValue = dateValue.getTime();
                    // converting time value into string format
                    String timeStamp = String.valueOf(timeValue);
                    // creating a timestamp out of time value by appending the processID along with it.
                    // this will aid in solving the issue of same timestamps of block records
                    String timeStampPID = timeStamp + "." + processID;
                    // generating random UUID's and assigning it to setUUID variable
                    blockUUID = UUID.randomUUID().toString();
                    // Splitting the input data into tokens and storing it in String[] format
                    DTokens = inputStrData.split(" +");
                    // declaring variable signedBlock
                    String signedBlock = "";
                    try {
                        // Invoking signData() method to apply digital signature on our block
                        byte[] digitalSign1 = signData(blockUUID.getBytes(), keysPair.getPrivate());
                        // digitalSign is then encoded using Base64 and assigned to signedBlock variable
                        signedBlock = Base64.getEncoder().encodeToString(digitalSign1);

                    } catch (Exception excpt) {
                        // exception handling
                        excpt.printStackTrace();
                    }

                    // Setting up values of the read-in data and updated with UUID, signedBlockID, ID of creator process,
                    // current timestamp
                    blockRec.setBlock_ID(blockUUID);
                    blockRec.setTimeStamp(timeStampPID);
                    blockRec.setSignedBlock_ID(signedBlock);
                    blockRec.setProcessCreation(String.valueOf(processID));
                    blockRec.setFirstName(DTokens[iFName]);
                    blockRec.setLastName(DTokens[iLName]);
                    blockRec.setSsnNumber(DTokens[iSsnNum]);
                    blockRec.setDateOfBirth(DTokens[iDob]);
                    blockRec.setMedDiag(DTokens[iMedDiag]);
                    blockRec.setMedTreat(DTokens[iMedTreatment]);
                    blockRec.setMedRX(DTokens[iMedRx]);

                    // Block is added to unverified block list
                    brList.add(blockRec);

                    // Creating string format of our unverified block record values that will aid in creating
                    // SHA256 Hash value later
                    String blockRecStr = blockRec.getBlock_ID() + blockRec.getFirstName() + blockRec.getLastName() +
                            blockRec.getSsnNumber() + blockRec.getDateOfBirth() + blockRec.getMedDiag() +
                            blockRec.getMedTreat() + blockRec.getMedRX() + blockRec.getProcessCreation();

                    // creating hash function of the block data by invoking MD2StringBuilder method
                    String hash256DigestStr = MD2StringBuilder(blockRecStr);

                    // block record aids in creating message digest that will be used later to verify whether the block
                    // is correctly signed by process or not.
                    String hashSigned = "";

                    // Signing the final unverified block using hash256DigestStr and private key
                    try {
                        byte[] digitalSign2 = signData(hash256DigestStr.getBytes(), keysPair.getPrivate());
                        hashSigned = Base64.getEncoder().encodeToString(digitalSign2);
                    } catch (Exception excpt) {
                        // exception handling
                        excpt.printStackTrace();
                    }
                    // setting the creator hash field with hash256DigestStr
                    blockRec.setHashMaker(hash256DigestStr);
                    // setting the creator signed hash with hashSigned
                    blockRec.setHashSignedMaker(hashSigned);
                    // Invoking sleep method
                    callSleep();
                }
            } catch (IOException ioException) {
                // exception handling
                ioException.printStackTrace();
            }

        } catch (FileNotFoundException e) {
            // exception handling
            e.printStackTrace();
        }
    }

    // Method to perform SHA256 hash on the block string; which then is converted to hexadecimal string
    // and returned back to the calling function
    private static String MD2StringBuilder(String blockRecStr) {
        StringBuffer hexString;
        String hash256DigestStr = "";
        try {
            // creating msgDigest object, using SHA256 algorithm for hashing
            MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");
            // passing blockRecStr data to above created msgDigest object
            // update() method is invoked to modify the digest using specified # of bytes
            msgDigest.update(blockRecStr.getBytes());
            // computing hash on the updated msgDigest object (output will be in byte[] format)
            byte[] byteData = msgDigest.digest();
            // Converting byte to hex format data
            hexString = new StringBuffer();
            for (byte byteDatum : byteData) {
                hexString.append(Integer.toString((byteDatum & 0xff) + 0x100, 16).substring(1));
            }
            hash256DigestStr = hexString.toString();
        } catch (NoSuchAlgorithmException exception) {
            // exception handling
            exception.printStackTrace();
        }
        // return hash256 string back to calling function
        return hash256DigestStr;
    }

    // Method used to sign data using the private key. This is a part of utility code
    // provided by prof. Elliott
    public static byte[] signData(byte[] bytesData, PrivateKey aPrivateKey)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(aPrivateKey);
        signer.update(bytesData);
        return (signer.sign());
    }

    // Method that allows the processes to verify data whether it has been signed with public key or not
    public static boolean verifySignature(byte[] bytesData, PublicKey publicKey, byte[] decode)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(publicKey);
        signer.update(bytesData);
        return (signer.verify(decode));
    }

    // Method to write the JSON record
    // This is a part of utility code provided by Prof. Elliott
    // Process 0 utilizes this code to write the entire blockchain ledger on the disk.
    // Process 0 writes entire ledger every time a block has been added to it.
    // bcLedger is our LinkedList that incorporates verified blocks that needs to be added into ledger
    public static void writeToJSON() {
        // converting java object to JSON and writing it on disk
        System.out.println("=========> In WriteJSON <=========\n");
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(BlockChainTaskToDo.bcLedger);
        //System.out.println(json);
        // Creating output file name - BlockchainLedger.json
        // and writing verified blocks - JSON object to a file
        try (FileWriter writeData = new FileWriter("BlockchainLedger.json")) {
            gson.toJson(BlockChainTaskToDo.bcLedger, writeData);
        } catch (IOException ioException) {
            // exception handling
            ioException.printStackTrace();
        }
    }

}

// Ports class that defines and sets ports for all the processes
class Ports {
    // StartServer port number
    public static int portBaseStartServer = 4600;
    // Public Key Server port number
    public static int portBaseKeyServer = 4710;
    // Unverified Block Server port number
    public static int portBaseUBServer = 4820;
    // Updated block chain server port number
    public static int portBaseUpdatedBC = 4930;

    // declaring startServer port variable
    public static int portStartServer;
    // declaring keyServer port variable
    public static int portKeyServer;
    // declaring unverified block port variable
    public static int portUBServer;
    // declaring blockchain port variable
    public static int portBCServer;

    // setPorts() method that takes in process ID and sets all the ports accordingly.
    // Format followed: portBase + processID
    public void setPorts(int processID) {
        // startServer port number
        portStartServer = portBaseStartServer + processID;
        // portKeyServer receives incoming public keys for each process ID
        portKeyServer = portBaseKeyServer + processID;
        // portUBServer receives unverified blocks for each process ID
        portUBServer = portBaseUBServer + processID;
        // portBCServer receives updated blockchain for each process ID
        portBCServer = portBaseUpdatedBC + processID;

    }
}

// Comparator class that will have our priority queue arrange blocks based on timestamp in it
// This is a part of utility code provided by Prof. Elliott
class BRComparator implements Comparator<BlockRecord> {
    @Override
    public int compare(BlockRecord blockRecord1, BlockRecord blockRecord2) {
        String date1 = blockRecord1.getTimeStamp();
        String date2 = blockRecord2.getTimeStamp();
        if (date1.equals(date2)) {
            return 0;
        }
        if (date1 == null) {
            return -1;
        }
        if (date2 == null) {
            return 1;
        }
        return date1.compareTo(date2);
    }
}

// Start Main Server class that invokes the worker class.
// This server will aid in starting all processes - by changing value for beginProcessFlag
// in its worker class. It will receive command - start from P2 and flip the flag to True -
// allowing other processes to continue operation
class StartMainServer implements Runnable {
    public void run() {
        // defined queue length
        int queueLength = 6;
        // declaring socket variable
        Socket socket;
        // displaying message on the terminal stating start of main server
        System.out.println("Main server started at: " + Ports.portStartServer);
        try {
            // assigning serverSocket object - its port number and queue length
            ServerSocket serverSocket = new ServerSocket(Ports.portStartServer, queueLength);
            while (true) {
                // accepting request
                socket = serverSocket.accept();
                // spawning a new worker thread and invokes worker class run()
                new SMSWorker(socket).start();
            }
        } catch (IOException ioException) {
            // exception handling
            ioException.printStackTrace();
        }
    }
}

// Worker class for StartMainServer class
class SMSWorker extends Thread {
    // declaring socket variable
    Socket socket;

    // constructor declaration - assigning socket to locally defined socket variable
    public SMSWorker(Socket socket) {
        this.socket = socket;
    }

    // run() method
    public void run() {
        try {
            //System.out.println("Inside start main server worker class!!!");
            // reading in input data from the socket
            BufferedReader inputData = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            //Once input data is received, changes the beginProcessFlag flag to true. Assuming that no other
            // commands will be sent over to this specific server.
            String dataRead = inputData.readLine();
            BlockChainTaskToDo.beginProcessFlag = true;
            // closes the socket connection
            socket.close();
        } catch (IOException ioException) {
            // exception handling
            ioException.printStackTrace();
        }
    }
}

// Public Key Server class that invokes its respective worker class
// PKS receives public keys from each and every process. This public key has 2 parts:
// a) original public key of the process + b) process ID of the sending process
// These are then saved in their specific array index.
class PublicKeysServer implements Runnable {
    public void run() {
        // defined queue length
        int queueLength = 6;
        // declaring socket variable
        Socket socket;
        // displaying message on the terminal stating launching of public key server port. It means the server is up and
        // running and will now receive the multicasted public keys by each processes
        System.out.println("Launching Public Keys Server at port: " + Ports.portKeyServer);
        try {
            // assigning serverSocket object - its port number and queue length
            ServerSocket serverSocket = new ServerSocket(Ports.portKeyServer, queueLength);
            while (true) {
                // accepting request
                socket = serverSocket.accept();
                // spawning a new worker thread and invokes public key server worker class run()
                new PKSWorker(socket).start();
            }
        } catch (IOException ioException) {
            // exception handling
            ioException.printStackTrace();
        }
    }
}

// Worker class for Public Key Server class
class PKSWorker extends Thread {
    // declaring key socket variable
    Socket keySocket;

    // constructor declaration - assigning socket to locally defined socket variable
    public PKSWorker(Socket socket) {
        this.keySocket = socket;
    }

    public void run() {
        try {
            // reading data from the input stream
            BufferedReader inputData = new BufferedReader(new InputStreamReader(keySocket.getInputStream()));
            // Splitting the inputData recieved in String array
            String[] dataRead = inputData.readLine().split(" ");
            // As process ID is int - we are converting string form to int form
            // for future indexing purpose
            int processID = Integer.parseInt(dataRead[0]);

            // Decoding the public key store in index position 1 in byte form
            // Converting from String to byte[] format
            byte[] publicKeyB = Base64.getDecoder().decode(dataRead[1]);
            // System.out.println("Key in Byte[] form again: " + publicKeyB);
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicKeyB);
            KeyFactory publicKeyFact = KeyFactory.getInstance("RSA");
            PublicKey RestoredKey = publicKeyFact.generatePublic(pubSpec);

            //Then, public key of each process is added to our publicKeyList
            BlockChainTaskToDo.publicKeyList[processID] = RestoredKey;
            // counter is incremented here
            BlockChainTaskToDo.pkCount++;
            // if we receive all 3 processes public key, then setting the flag = true
            if (BlockChainTaskToDo.pkCount == 3) {
                BlockChainTaskToDo.pkFlag = true;
            }
            // Displaying message on terminal confirming public key has been received for all 3 processes
            System.out.println("Recieved public key for Process ID: " + processID);
            // closes the socket connection
            keySocket.close();
        } catch (Exception exception) {
            // exception handling
            exception.printStackTrace();
        }
    }
}

// Unverified Block Server class that invokes its respective worker class
// Receives blocks that are read in by each process through input file or those blocks are requires to be
// re-verified because of change in blockchain ledger
class UVBlockServer implements Runnable {

    // declaring our local blockQueue variable of type BlockRecord
    BlockingQueue<BlockRecord> blockQueue;

    // constructor declaration which assign the queue to our locally defined block queue variable
    public UVBlockServer(BlockingQueue<BlockRecord> blockQueue) {
        this.blockQueue = blockQueue;
    }

    // starting-up the unverified block server for receiving blocks
    @Override
    public void run() {
        // defined queue length - number of incoming request that can be stored in queue
        int queueLength = 6;
        // declaring UVBSocket socket variable
        Socket UVBSocket;

        // Display message stating the launch of unverified block server along with its port number
        System.out.println("Launching the Unverified Block Server input thread using " + Ports.portUBServer);
        try {
            // creating server socket object UVBlockServer
            ServerSocket UVBlockServer = new ServerSocket(Ports.portUBServer, queueLength);
            while (true) {
                // accepting request and receiving a new unverified block to store in the queue
                UVBSocket = UVBlockServer.accept();
                // spawning worker thread to process the incoming request
                new UVBlockServerWorker(UVBSocket).start();
            }
        } catch (IOException ioException) {
            // exception handling
            ioException.printStackTrace();
        }
    }
}

// Worker class for Un-Verified Block Server class
// Receives UVB and places into priority queue
class UVBlockServerWorker extends Thread {
    // declaring uvbSocket socket
    Socket uvbSocket;

    // constructor declaration assigning uvbSocket to locally defined socket variable
    public UVBlockServerWorker(Socket uvbSocket) {
        this.uvbSocket = uvbSocket;
    }

    @Override
    public void run() {
        try {
            // Reading in input data from uvbSocket
            BufferedReader inputData = new BufferedReader(new InputStreamReader(uvbSocket.getInputStream()));
            // declaring input string variable
            String inputString;
            // creating gson object
            Gson gson = new Gson();
            // creating string buffer object
            StringBuffer strBuffer = new StringBuffer();
            // Storing input read-in data into string buffer in json format
            while ((inputString = inputData.readLine()) != null) {
                strBuffer.append(inputString);
                //System.out.println("String Buffer: " + strBuffer.toString());
            }
            // Marshal JSON data into java object brInput
            BlockRecord brInput = gson.fromJson(strBuffer.toString(), BlockRecord.class);
            //System.out.println("BR Input: " + brInput.toString());
            System.out.println("Inserted in the priority blocking queue: " + brInput.getBlock_ID() + "\n");
            // Place the java object - brInput (block record input) into concurrent priority queue
            // Each process has its own queue
            BlockChainTaskToDo.blockQueue.put(brInput);
            //System.out.println("Elements in queue: " + BlockChainTaskToDo.blockQueue);

            // closes the socket connection
            uvbSocket.close();
        } catch (Exception exception) {
            // exception handling
            exception.printStackTrace();
        }
    }
}

// Updated BlockChain Server class - In this implementation, our UBlockchainServer will receive blocks that
// are verified and then, updates each processes ledger. After connection to the socket has been established, the verified block
// is sent. It is read in using the JSON object.
class UBlockchainServer implements Runnable {
    @Override
    public void run() {
        // defined queue length - number of incoming request that can be stored in queue
        int queueLength = 6;
        // declaring bcSocket variable
        Socket bcSocket;
        // Display message stating the launch of updated blockchain server along with its port number
        System.out.println("Launching the Blockchain server input thread using " + Ports.portBCServer);
        try {
            // creating server socket object that takes in port number for bc server and queue length
            ServerSocket servsock = new ServerSocket(Ports.portBCServer, queueLength);
            while (true) {
                // accepts the incoming request
                bcSocket = servsock.accept();
                // spawn a worker thread to process incoming request
                new UpdatedBlockchainWorker(bcSocket).start();
            }
        } catch (IOException ioe) {
            // exception handling
            ioe.printStackTrace();
        }
    }
}

// Worker class for Updated blockchain Server class
// Receives verified blocks rather than entire blockchain ledger.
// These verified block is then added to THIS process ledger
class UpdatedBlockchainWorker extends Thread {
    // declaring a local socket variable
    Socket bcSocket;

    // constructor declaration that assigns the incoming socket data to locally defined socket variable for further
    // processing
    public UpdatedBlockchainWorker(Socket bcSocket) {
        this.bcSocket = bcSocket;
    }

    @Override
    public void run() {
        try {
            // Reading data in from bc socket input stream
            BufferedReader inputData = new BufferedReader(new InputStreamReader(bcSocket.getInputStream()));
            // creating gson object
            Gson gson = new Gson();
            // declaring string variable
            String brData;
            // creating string buffer object
            StringBuffer brDataBuff = new StringBuffer();
            // Storing input read-in data into string buffer in json format
            while ((brData = inputData.readLine()) != null) {
                brDataBuff.append(brData);
            }
            // Parsing JSON data into java object brInput
            BlockRecord blockRecordIn = gson.fromJson(brDataBuff.toString(), BlockRecord.class);
            // Verifying whether the block is in blockchain ledger or not
            // if not, adds the block to THIS process's copy of ledger
            if (!BlockChainTaskToDo.isDuplicate(blockRecordIn)) {
                BlockChainTaskToDo.bcLedger.add(0, blockRecordIn);
                System.out.println("Verified Block added to BlockChain Ledger");
                System.out.println("Verified Block Count in the Ledger is: " + BlockChainTaskToDo.bcLedger.size());

            }
            // If process ID is 0 - then writes the entire blockchain ledger to disk
            // by invoking the writeToJSON() method
            if (BlockChainTaskToDo.processID == 0) {
                BlockChainTaskToDo.writeToJSON();
            }
            // closes the socket connection
            bcSocket.close();
        } catch (IOException ioException) {
            // exception handling
            ioException.printStackTrace();
        }
    }
}

// Work class of BlockChain. As input to its constructor, we are passing the priority queue of THIS process
// that holds the UVB. The block is popped out from the queue and stored in a temporary variable for further processing.
// This record is then converted to string and digital signature of the block is verified to confirm that it has been
// signed by its process.

class WorkPuzzle implements Runnable {

    // declaring local block Queue variable
    BlockingQueue<BlockRecord> blockQ;

    // A pool of alpha numeric string - used to create our random string - our correct guess
    private static final String alphaNumericStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // constructor declaration that takes in queue and binds to locally declared queue variable
    public WorkPuzzle(PriorityBlockingQueue<BlockRecord> blockQueue) {
        this.blockQ = blockQueue;
    }

    @Override
    public void run() {
        try {
            while (true) {
                // Pulls in one block record from the queue at a time
                BlockRecord blockRec = BlockChainTaskToDo.blockQueue.take();
                // string format of our block record
                // Will be used in message digest hash
                String blockRecStr = blockRec.getBlock_ID() + blockRec.getFirstName() +
                        blockRec.getLastName() + blockRec.getSsnNumber() +
                        blockRec.getDateOfBirth() + blockRec.getMedDiag() +
                        blockRec.getMedTreat() + blockRec.getMedRX() +
                        blockRec.getProcessCreation();
                // Stores are random seed string
                String randomStr;
                // Random seed string concatenated with our current data
                String concatenateStr;
                // String created from SHA256 hash
                String hashStr;

                boolean isHashVerified;
                boolean isBlockIDVerified;
                // Checking whether the current block is already present in ledger or not!
                if (BlockChainTaskToDo.isDuplicate(blockRec) && blockRec != null) {
                    System.out.println("Duplicated Block Record in BlockChain");
                    continue;
                }

                // Verifying the signed BlockID using creator process public key
                isBlockIDVerified = BlockChainTaskToDo.verifySignature(blockRec.getBlock_ID().getBytes(),
                        BlockChainTaskToDo.publicKeyList[Integer.parseInt(blockRec.getProcessCreation())],
                        Base64.getDecoder().decode(blockRec.getSignedBlock_ID()));

                String messageBlock = isBlockIDVerified ? "Block ID Signed" : "Block ID not Signed";
                System.out.println(messageBlock);

                // Verifying the creator process's signed SHA256 hash value of Data
                isHashVerified = BlockChainTaskToDo.verifySignature(blockRec.getHashMaker().getBytes(),
                        BlockChainTaskToDo.publicKeyList[Integer.parseInt(blockRec.getProcessCreation())],
                        Base64.getDecoder().decode(blockRec.getHashSignedMaker()));

                String messageHash = isHashVerified ? "Hash Signed" : "Hash not Signed";
                System.out.println(messageHash);

                // Fetching block id of previous block in our ledger
                String previousBlockID = BlockChainTaskToDo.bcLedger.get(0).getBlock_ID();
                // Work Number will be between 0000 (0) and FFFF (65535)
                // Used to find out whether the puzzle/ work is solved or not
                int workNum;
                // If puzzle is solved, adds block to this variable
                String updatedBlock = blockRecStr;
                // Adding first part of the DATA : winning hash of previous block to the new updated block
                updatedBlock = updatedBlock + BlockChainTaskToDo.bcLedger.get(0).getWinningHashValue();
                //System.out.println(updatedBlock);
                // allows to solve puzzle if the block record is not already a part of the ledger
                if (!BlockChainTaskToDo.isDuplicate(blockRec)) {
                    try {

                        // Limiting for how long this example can try
                        for (int i = 1; i < 20; i++) {
                            // Getting a new random AlphaNumeric Seed String - our guess
                            randomStr = randomAlphaNumeric(8);
                            // Adding third part of the DATA : random seed string to the our updated BlockData
                            concatenateStr = updatedBlock + randomStr;
                            System.out.println("Final BlockData consisting of 3 parts: Previous Hash, Actual Data, and" +
                                    "Random Seed String (before hashing): " + concatenateStr);

                            // Getting hash value of our BlockData
                            MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");
                            byte[] bytesHash = msgDigest.digest(concatenateStr.getBytes(StandardCharsets.UTF_8));

                            // Converting into a string of hex values
                            hashStr = byteArray2Str(bytesHash);
                            System.out.println("Hash Value of the Final BlockData is: " + hashStr);

                            // Between 0000 (0) and FFFF (65535)
                            // Getting numeric value of 1st 16 bits,
                            // Then, check it to see if it is less than 20,000 - it means our puzzle is solved
                            workNum = Integer.parseInt(hashStr.substring(0, 4), 16);
                            System.out.println("First 16 bits in Hex and Decimal: " + hashStr.substring(0, 4) + " and " + workNum);

                            // if workNum is not less that 20k then, rework
                            if (!(workNum < 20000)) {
                                System.out.format("%d is not less than 20,000. Solving Puzzle Again!\n\n", workNum);
                            }
                            // When we meet our threshold - puzzle solved
                            if (workNum < 20000) {
                                // Ensuring that previous block record (block ID) is same as the block id when we started
                                // this process i.e. making sure the block chain ledger has not be updated.
                                // If it has been updated,  then sending the block back for reverification
                                if (!previousBlockID.equals(BlockChainTaskToDo.bcLedger.get(0).getBlock_ID())) {
                                    System.out.println("Reading BlockData from Work Loop");
                                    BlockChainTaskToDo.sendBlock2Ledger(blockRec, "reVerifyBlock");
                                }
                                // If Blockchain ledger has not been updated, then adding block to ledger
                                else {
                                    // Setting winning hash value for the current data block
                                    blockRec.setWinningHashValue(hashStr);
                                    // Setting the random seed string for the current data block
                                    blockRec.setRandomSeedValue(randomStr);
                                    System.out.format("%d is less than 20,000. Puzzle Solved!\n", workNum);
                                    System.out.println("Winning Random Seed String: " + randomStr);
                                    // Setting previous blockData winning hash value to the current BlockData
                                    blockRec.setPreviousHashValue(BlockChainTaskToDo.bcLedger.get(0).getWinningHashValue());

                                    // Getting previous block number; so that we can increment it and
                                    // set updated block number field for current block data
                                    int blockNumber = Integer.parseInt(BlockChainTaskToDo.bcLedger.get(0).getBlockNumber());
                                    blockNumber++;
                                    blockRec.setBlockNumber(String.valueOf(blockNumber));
                                    // Setting the process ID number that verified this BlockData
                                    blockRec.setProcessIDVerification(String.valueOf(BlockChainTaskToDo.processID));

                                    //Used to sign the winning hash value with verifier digital signature
                                    String signHashVerifier;

                                    byte[] digitalSign = BlockChainTaskToDo.signData(hashStr.getBytes(),
                                            BlockChainTaskToDo.keysPair.getPrivate());
                                    signHashVerifier = Base64.getEncoder().encodeToString(digitalSign);

                                    blockRec.setWinningSignedHashValue(signHashVerifier);

                                    // Finally, adding the signed Block to Ledger
                                    BlockChainTaskToDo.bcLedger.add(0, blockRec);
                                    // Displaying message on the terminal
                                    System.out.println("Block added to Blockchain Ledger.");
                                    System.out.println("Verified Blocks count is: " + BlockChainTaskToDo.bcLedger.size());

                                    // Multicasting the verified block to all the processes
                                    BlockChainTaskToDo.sendBlock2Ledger(blockRec, "bcLedgerUpdate");
                                    continue;
                                }
                                break;
                            }
                            if (BlockChainTaskToDo.isDuplicate(blockRec)) {
                                // Periodically checking if current record has already been verified or not.
                                // If it is, then abandoning this process's attempt to verify the block
                                System.out.println("Duplicate Block - Already verified!!");
                                break;
                            }
                            // Invoking sleep method
                            BlockChainTaskToDo.callSleep();
                        }
                    } catch (Exception excpt) {
                        // Exception handling
                        excpt.printStackTrace();
                    }
                }
            }
        } catch (Exception excpt) {
            excpt.printStackTrace();
        }
    }

    // Method that creates random seed string (alphanumeric) from count provided
    // Part of utility code provided by Prof. Elliott
    public static String randomAlphaNumeric(int count) {
        StringBuilder stringBuilder = new StringBuilder();
        while (count-- != 0) {
            int character = (int) (Math.random() * alphaNumericStr.length());
            stringBuilder.append(alphaNumericStr.charAt(character));
        }
        return stringBuilder.toString();
    }

    // Method that takes in byte array argument and converts to string format.
    // Part of utility code provided by Prof. Elliott
    public static String byteArray2Str(byte[] ba2s) {
        StringBuilder hexString = new StringBuilder(ba2s.length * 2);
        for (byte byteA2S : ba2s) {
            hexString.append(String.format("%02X", byteA2S));
        }
        return hexString.toString();
    }
}