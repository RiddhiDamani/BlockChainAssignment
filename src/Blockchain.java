import com.google.gson.Gson;
import com.google.gson.GsonBuilder;


import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;

public class Blockchain {
    private static int processID;

    public static void main(String[] args) {
        // queue length
        int queueLength = 6;
        if(args.length < 1) {
            processID = 0;
        }
        switch (args[0]) {
            case "0" : processID = 0;
                       break;
            case "1" : processID = 1;
                       break;
            case "2" : processID = 2;
                       break;
            default:   processID = 0;
                       break;
        }

        BlockChainTaskToDo bcTtd = new BlockChainTaskToDo(processID);
    }
}
class BlockRecord {
    private String block_ID;
    private String signedBlock_ID;
    private String timeStamp;
    private String blockNumber;
    private String firstName;
    private String lastName;
    private String dateOfBirth;
    private String ssnNumber;
    private String medicalCondition;
    private String treatmentRec;
    private String medicineRec;
    private String hashMaker;
    private String hashSignedMaker;
    private String previousHashValue;
    private String winningHashValue;
    private String winningSignedHashValue;
    private String randomSeedValue;
    private String processIDVerification;
    private String processCreation;
    private UUID uuid;

    public String getBlock_ID() {
        return block_ID;
    }

    public void setBlock_ID(String block_ID) {
        this.block_ID = block_ID;
    }

    public String getSignedBlock_ID() {
        return signedBlock_ID;
    }

    public void setSignedBlock_ID(String signedBlock_ID) {
        this.signedBlock_ID = signedBlock_ID;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getBlockNumber() {
        return blockNumber;
    }

    public void setBlockNumber(String blockNumber) {
        this.blockNumber = blockNumber;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(String dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }

    public String getSsnNumber() {
        return ssnNumber;
    }

    public void setSsnNumber(String ssnNumber) {
        this.ssnNumber = ssnNumber;
    }

    public String getMedicalCondition() {
        return medicalCondition;
    }

    public void setMedicalCondition(String medicalCondition) {
        this.medicalCondition = medicalCondition;
    }

    public String getTreatmentRec() {
        return treatmentRec;
    }

    public void setTreatmentRec(String treatmentRec) {
        this.treatmentRec = treatmentRec;
    }

    public String getMedicineRec() {
        return medicineRec;
    }

    public void setMedicineRec(String medicineRec) {
        this.medicineRec = medicineRec;
    }

    public String getHashMaker() {
        return hashMaker;
    }

    public void setHashMaker(String hashMaker) {
        this.hashMaker = hashMaker;
    }

    public String getHashSignedMaker() {
        return hashSignedMaker;
    }

    public void setHashSignedMaker(String hashSignedMaker) {
        this.hashSignedMaker = hashSignedMaker;
    }

    public String getPreviousHashValue() {
        return previousHashValue;
    }

    public void setPreviousHashValue(String previousHashValue) {
        this.previousHashValue = previousHashValue;
    }

    public String getWinningHashValue() {
        return winningHashValue;
    }

    public void setWinningHashValue(String winningHashValue) {
        this.winningHashValue = winningHashValue;
    }

    public String getWinningSignedHashValue() {
        return winningSignedHashValue;
    }

    public void setWinningSignedHashValue(String winningSignedHashValue) {
        this.winningSignedHashValue = winningSignedHashValue;
    }

    public String getRandomSeedValue() {
        return randomSeedValue;
    }

    public void setRandomSeedValue(String randomSeedValue) {
        this.randomSeedValue = randomSeedValue;
    }

    public String getProcessIDVerification() {
        return processIDVerification;
    }

    public void setProcessIDVerification(String processIDVerification) {
        this.processIDVerification = processIDVerification;
    }

    public String getProcessCreation() {
        return processCreation;
    }

    public void setProcessCreation(String processCreation) {
        this.processCreation = processCreation;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }
}
class BlockChainTaskToDo {
    public static int processID;
    public static int totalNumProcesses = 3;
    public static String sName = "localhost";
    public static boolean beginProcessFlag = false;
    public static boolean pkFlag = false;
    public static int pkCount = 0;
    public static String blockchain = "[First block]";
    public static KeyPair keysPair;

    public static PublicKey[] publicKeyList = new PublicKey[totalNumProcesses];
    // Blockchain Ledger - contains verified blocks in it.
    public static LinkedList<BlockRecord> bcLedger = new LinkedList<>();
    public static final PriorityBlockingQueue<BlockRecord> blockQueue = new PriorityBlockingQueue<>(100, new BRComparator());
    static LinkedList<BlockRecord> brList = new LinkedList<>();

    private static final int iFName = 0;
    private static final int iLName = 1;
    private static final int iDob = 2;
    private static final int iSsnNum = 3;
    private static final int iMedDiag = 4;
    private static final int iMedTreatment = 5;
    private static final int iMedRx = 6;

    public BlockChainTaskToDo(int processID) {
        this.processID = processID;
        new Ports().setPorts(processID);
        run();
    }

    public void run() {
        System.out.println("Riddhi Damani's BlockChain in progress..\n");
        System.out.println("Currently, utilizing input file: " + String.format("BlockInput%d.txt", processID));

        new Thread(new StartMainServer()).start();
        new Thread(new PublicKeysServer()).start();
        new Thread(new UVBlockServer(blockQueue)).start();
        new Thread(new UBlockchainServer()).start();
        try {
            Thread.sleep(2000);
        }
        catch (Exception exception) {
            exception.printStackTrace();
        }

        if(processID == 2) {
            startAllProcesses();
        }

        try{
            keysPair = generateKeyPair(444);
        }
        catch (Exception exception){
            exception.printStackTrace();
        }

        while (!beginProcessFlag) {
            callSleep();
        }
        System.out.println("Launching...");
        multiCastPublicKeys();
        while(!pkFlag) {
            callSleep();
        }

        if(processID == 0) {
            createGenesisBlock();
        }

        readInputFile();
        multiCast2Processes();

        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        new Thread(new WorkPuzzle(blockQueue)).start();
    }

    public void multiCast2Processes() {
        Socket mcpSocket;
        PrintStream send2Server;
        BlockRecord tempBlockRec;
        Iterator<BlockRecord> iterator = brList.iterator();
        try {
            while (iterator.hasNext()){
                tempBlockRec = iterator.next();
                String blockRec = jsonBuilder(tempBlockRec);
                System.out.println("Inside MultiCast Processes:");
                System.out.println("Block Rec:" + blockRec);
                for(int i = 0; i < totalNumProcesses; i++){
                    mcpSocket = new Socket(sName, Ports.portBaseUBServer + i);
                    send2Server = new PrintStream(mcpSocket.getOutputStream());
                    send2Server.println(blockRec);
                    send2Server.flush();
                    mcpSocket.close();
                }
            }
        }
        catch (Exception excpt){
            excpt.printStackTrace();
        }
    }

    public static void callSleep() {
        try {
            Thread.sleep(1000);
        }
        catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    public static boolean isDuplicate(BlockRecord blockRecordIn) {
        BlockRecord checkRec = blockRecordIn;
        Iterator<BlockRecord> looper = bcLedger.iterator();
        while(looper.hasNext()){
            if (checkRec.getBlock_ID().equals(looper.next().getBlock_ID()))
                return true;
        }
        return false;
    }

    public static KeyPair generateKeyPair(long randomSeed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(randomSeed);
        keyGenerator.initialize(1024, rng);
        return (keyGenerator.generateKeyPair());
    }

    public void multiCastPublicKeys() {
        Socket mcpkSocket;
        PrintStream send2Server;
        byte[] publicKey = keysPair.getPublic().getEncoded();
        String strPublicKey = Base64.getEncoder().encodeToString(publicKey);
        System.out.println("Public Key Created for MultiCasting: " + strPublicKey);
        try{
            for(int i = 0; i< totalNumProcesses; i++) {
                mcpkSocket = new Socket(sName, Ports.portBaseKeyServer + i);
                send2Server = new PrintStream(mcpkSocket.getOutputStream());
                String pIDPublicKey = processID + " " + strPublicKey;
                send2Server.println(pIDPublicKey);
                send2Server.flush();
                mcpkSocket.close();
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    public boolean startAllProcesses() {
        Socket startSocket;
        PrintStream send2Server;
        try {
            for(int i = 0; i < totalNumProcesses; i++) {
                startSocket = new Socket(sName, Ports.portBaseStartServer + i);
                send2Server = new PrintStream(startSocket.getOutputStream());
                send2Server.println("start");
                System.out.println("Sending Start");
                send2Server.flush();
                startSocket.close();
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return true;
    }

    public static void createGenesisBlock(){

        String SHA256Data = "";
        BlockRecord  blockRec = new BlockRecord();

        Date dateValue = new Date();
        long timeValue = dateValue.getTime();
        String strTimeValue = String.valueOf(timeValue);
        String timeStamped = strTimeValue + "." + processID;
        String setUUID = UUID.randomUUID().toString();

        blockRec.setTimeStamp(timeStamped);
        blockRec.setBlock_ID(setUUID);
        blockRec.setFirstName("George");
        blockRec.setLastName("Bush");
        blockRec.setSsnNumber("111-00-1111");
        blockRec.setDateOfBirth("1890.10.10");
        blockRec.setMedicalCondition("Cancer");
        blockRec.setTreatmentRec("Chemotheraphy");
        blockRec.setMedicineRec("HealthyFood");
        blockRec.setPreviousHashValue("1111111111");
        blockRec.setBlockNumber("1");

        String blockRecord = blockRec.getBlock_ID() +
                blockRec.getFirstName() +
                blockRec.getLastName() +
                blockRec.getSsnNumber() +
                blockRec.getDateOfBirth() +
                blockRec.getMedicalCondition() +
                blockRec.getTreatmentRec() +
                blockRec.getMedicineRec();

        //System.out.println("Dummy Block Record: " + blockRecord);

        MessageDigest msgDigest;
        String encodedBlock = null;

        try{
            msgDigest = MessageDigest.getInstance("SHA-256");
            //System.out.println("Msg Digest:" + msgDigest);
            // update() method is invoked to modify the digest using specified # of bytes
            msgDigest.update(blockRecord.getBytes());
            // digest() method is invoked to finish the hash computations - adding padding if needed!
            byte[] hashData = msgDigest.digest();
            //System.out.println("hashData:" + hashData);

            // Converting byte to hex format data
            StringBuffer strBuff = new StringBuffer();
            for (byte hashDatum : hashData) {
                strBuff.append(Integer.toString((hashDatum & 0xff) + 0x100, 16).substring(1));
            }

            // For ease of looking at it, we'll save it as a string.
            SHA256Data = strBuff.toString();
            //System.out.println("SHA256Data: " + SHA256Data);
            // Here we just assume the first hash is a winner. No real *work*.
            blockRec.setWinningHashValue(SHA256Data);
        }
        catch(NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
        }

        bcLedger.add(0, blockRec);
        System.out.println("Size of the BlockChain Ledger is: " + bcLedger.size());

        if(processID == 0){
            System.out.println("Writing first block to BC ledger");
            sendBlock2Ledger(blockRec, "bcLedgerUpdate");
            writeToJSON();
        }
    }

    public static void sendBlock2Ledger(BlockRecord blockRec, String operation) {
        Socket sblSocket;
        PrintStream send2Server;
        switch (operation) {
            case "bcLedgerUpdate" :
                try {
                    for (int i = 0; i <totalNumProcesses; i++) {
                        sblSocket = new Socket(sName, Ports.portBaseUpdatedBC + i);
                        send2Server = new PrintStream(sblSocket.getOutputStream());

                        send2Server.println(jsonBuilder(blockRec)); //uses my buildString function to marshall record as JSON
                        System.out.println("Verified block broadcasting " + blockRec.getBlock_ID());
                        send2Server.flush();
                        sblSocket.close();
                    }
                } catch (IOException ioException) {
                    ioException.printStackTrace();
                }
                break;
            case "reVerifyBlock" :
                try {
                    System.out.println("Inside Switch reverify block!");
                    for (int j = 0; j < totalNumProcesses; j++) {
                        sblSocket = new Socket(sName, Ports.portBaseUpdatedBC + j);
                        send2Server = new PrintStream(sblSocket.getOutputStream());
                        send2Server.println(jsonBuilder(blockRec));
                        System.out.println("Block is being broadcasted: " + blockRec.getBlock_ID());
                        send2Server.flush();
                        sblSocket.close();
                    }
                } catch (IOException ioException) {
                    ioException.printStackTrace();
                }
                break;

        }

    }

    public static String jsonBuilder(BlockRecord blockRec) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(blockRec);
        return json;
    }

    public static void readInputFile() {
        String inputFile = String.format("BlockInput%d.txt", processID);
        try {
            BufferedReader inputData = new BufferedReader(new FileReader(inputFile));
            String[] tokensNum = new String[10];
            String inputStrData;
            String blockUUID;

            try {
                while ((inputStrData = inputData.readLine()) != null) {
                    Date dateValue = new Date();
                    BlockRecord  blockRec = new BlockRecord();
                    long timeValue = dateValue.getTime();
                    String timeStamp = String.valueOf(timeValue);
                    String timeStampPID = timeStamp + "." + processID ;
                    blockUUID = UUID.randomUUID().toString();
                    tokensNum = inputStrData.split(" +");
                    String blockIDSigned = "";
                    try{
                        byte[] digitalSign = signData(blockUUID.getBytes(), keysPair.getPrivate());
                        blockIDSigned = Base64.getEncoder().encodeToString(digitalSign);

                    }catch(Exception excpt){
                        excpt.printStackTrace();
                    }

                    blockRec.setTimeStamp(timeStampPID);
                    blockRec.setBlock_ID(blockUUID);
                    blockRec.setSignedBlock_ID(blockIDSigned);
                    blockRec.setFirstName(tokensNum[iFName]);
                    blockRec.setLastName(tokensNum[iLName]);
                    blockRec.setSsnNumber(tokensNum[iSsnNum]);
                    blockRec.setDateOfBirth(tokensNum[iDob]);
                    blockRec.setMedicalCondition(tokensNum[iMedDiag]);
                    blockRec.setTreatmentRec(tokensNum[iMedTreatment]);
                    blockRec.setMedicineRec(tokensNum[iMedRx]);
                    blockRec.setProcessCreation(String.valueOf(processID));

                    brList.add(blockRec);

                    String blockRecStr = blockRec.getBlock_ID() + blockRec.getFirstName() + blockRec.getLastName() +
                            blockRec.getSsnNumber() + blockRec.getDateOfBirth() + blockRec.getMedicalCondition() +
                            blockRec.getTreatmentRec() + blockRec.getMedicineRec() + blockRec.getProcessCreation();
                    System.out.println("BlockRecord String:" + blockRecStr);

                    String hashDigestStr = "";
                    String hashSigned = "";
                    try{
                        MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");
                        msgDigest.update (blockRecStr.getBytes());
                        byte byteData[] = msgDigest.digest();

                        // CDE: Convert the byte[] to hex format. THIS IS NOT VERFIED CODE:
                        StringBuffer strBuff = new StringBuffer();
                        for (int i = 0; i < byteData.length; i++) {
                            strBuff.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
                        }
                        hashDigestStr = strBuff.toString(); // For ease of looking at it, we'll save it as a string.
                    }
                    catch(NoSuchAlgorithmException exception){
                        exception.printStackTrace();
                    };
                    try {
                        byte[] digitalSign = signData(hashDigestStr.getBytes(), keysPair.getPrivate());
                        hashSigned = Base64.getEncoder().encodeToString(digitalSign);
                    }
                    catch (Exception excpt) {
                        excpt.printStackTrace();
                    }
                    blockRec.setHashMaker(hashDigestStr);
                    blockRec.setHashSignedMaker(hashSigned);
                    callSleep();
                }
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

    }

    // Review once!!
    public static byte[] signData(byte[] bytesData, PrivateKey aPrivateKey)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(aPrivateKey);
        signer.update(bytesData);
        return (signer.sign());
    }

    public static boolean verifySignature(byte[] bytesData, PublicKey publicKey, byte[] decode)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(publicKey);
        signer.update(bytesData);
        return (signer.verify(decode));
    }

    public static void writeToJSON() {
        System.out.println("=========> In WriteJSON <=========\n");
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(BlockChainTaskToDo.bcLedger);
        System.out.println(json);
        try (FileWriter writeData = new FileWriter("BlockchainLedger.json")) {
            gson.toJson(BlockChainTaskToDo.bcLedger, writeData);
        }
        catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }

}

class Ports {
    public static int portBaseStartServer = 4600;
    public static int portBaseKeyServer = 4710;
    public static int portBaseUBServer = 4820;
    public static int portBaseUpdatedBC = 4930;

    public static int portStartServer;
    public static int portKeyServer;
    public static int portUBServer;
    public static int portBCServer;

    public void setPorts(int processID){
        portStartServer = portBaseStartServer + processID;
        portUBServer = portBaseUBServer + processID;
        portBCServer = portBaseUpdatedBC + processID;
        portKeyServer =	portBaseKeyServer + processID;
    }
}
class BRComparator implements Comparator<BlockRecord> {

    @Override
    public int compare(BlockRecord blockRecord1, BlockRecord blockRecord2) {
        String date1 = blockRecord1.getTimeStamp();
        String date2 = blockRecord2.getTimeStamp();
        if (date1 == date2) {
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
class StartMainServer implements Runnable {
    public void run() {
        //System.out.println("Inside start main server!!!");
        int queueLength = 6;
        Socket socket;
        System.out.println("Main server started at: " + Integer.toString(Ports.portStartServer));
        try {
            ServerSocket serverSocket = new ServerSocket(Ports.portStartServer, queueLength);
            while (true) {
                socket = serverSocket.accept();
                new SMSWorker(socket).start();
            }
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }
}
class SMSWorker extends Thread {
    Socket socket;
    public SMSWorker(Socket socket) {
        this.socket = socket;
    }
    public void run() {
        try {
            //System.out.println("Inside start main server worker class!!!");
            BufferedReader inputData = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String dataRead = inputData.readLine();
            BlockChainTaskToDo.beginProcessFlag = true;
            socket.close();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }

    }
}
class PublicKeysServer implements Runnable {
    public void run() {
        int queueLength = 6;
        Socket socket;
        System.out.println("Launching Public Keys Server at port: " + Integer.toString(Ports.portKeyServer));
        try {
            ServerSocket serverSocket = new ServerSocket(Ports.portKeyServer, queueLength);
            while (true) {
                socket = serverSocket.accept();
                new PKSWorker(socket).start();
            }
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }
}
class PKSWorker extends Thread {
    Socket keySocket;
    public PKSWorker(Socket socket) {
        this.keySocket = socket;
    }
    public void run() {
        try {
            BufferedReader inputData = new BufferedReader(new InputStreamReader(keySocket.getInputStream()));
            String[] dataRead = inputData.readLine().split(" ");
            int processID = Integer.parseInt(dataRead[0]);

            // ---- Need to go through this once again ----
            byte[] publicKeyB  = Base64.getDecoder().decode(dataRead[1]);
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicKeyB);
            KeyFactory publicKeyFact = KeyFactory.getInstance("RSA");
            PublicKey RestoredKey = publicKeyFact.generatePublic(pubSpec);

            // ---- Need to go through this once again ----

            BlockChainTaskToDo.publicKeyList[processID] = RestoredKey;

            BlockChainTaskToDo.pkCount++;
            BlockChainTaskToDo.pkFlag = (BlockChainTaskToDo.pkCount == 3) ? true : false;

            System.out.println("Recieved key for Process ID: " + processID);
            keySocket.close();
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
}
class UVBlockServer implements Runnable {

    BlockingQueue<BlockRecord> blockQueue;

    public UVBlockServer(BlockingQueue<BlockRecord> blockQueue) {
        this.blockQueue = blockQueue;
    }

    @Override
    public void run() {
        int queueLength = 6;
        Socket UVBSocket;

        System.out.println("Launching the Unverified Block Server input thread using " +
                Integer.toString(Ports.portUBServer));
        try {
            ServerSocket UVBlockServer = new ServerSocket(Ports.portUBServer, queueLength);
            while (true) {
                UVBSocket = UVBlockServer.accept(); 
                new UVBlockServerWorker(UVBSocket).start(); // So start a thread to process it.
            }
        }
        catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }
}
class UVBlockServerWorker extends Thread {
    Socket uvbSocket;
    public UVBlockServerWorker(Socket uvbSocket) {
        this.uvbSocket = uvbSocket;
    }

    // Review once again!!
    public void run() {
        try {
            BufferedReader inputData = new BufferedReader(new InputStreamReader(uvbSocket.getInputStream()));
            Gson gson = new Gson();
            StringBuffer strBuffer = new StringBuffer();
            String inputString;
            while ((inputString = inputData.readLine()) != null) {
                strBuffer.append(inputString);
            }
            BlockRecord brInput = gson.fromJson(strBuffer.toString(), BlockRecord.class);
            System.out.println("Inserted in the priority blocking queue: " + brInput.getBlock_ID() + "\n");
            BlockChainTaskToDo.blockQueue.put(brInput);
            uvbSocket.close();
        }
        catch (Exception exception) {
            exception.printStackTrace();
        }
    }
}
class UBlockchainServer implements Runnable {
    @Override
    public void run() {
        int queueLength = 6;
        Socket bcSocket;
        System.out.println("Launching the Blockchain server input thread using " +
                Integer.toString(Ports.portBCServer));
        try{
            ServerSocket ss = new ServerSocket(Ports.portBCServer, queueLength);
            while (true) {
                bcSocket = ss.accept();
                new UpdatedBlockchainWorker(bcSocket).start();
            }
        }
        catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}
class UpdatedBlockchainWorker extends Thread {
    Socket bcSocket;

    public UpdatedBlockchainWorker(Socket bcSocket) {
        this.bcSocket = bcSocket;
    }
    // Review once again
    public void run() {
        try {
            BufferedReader inputData = new BufferedReader(new InputStreamReader(bcSocket.getInputStream()));
            String brData = "";
            StringBuffer brDataBuff = new StringBuffer();
            Gson gson = new Gson();
            while ((brData = inputData.readLine()) != null) {
                brDataBuff.append(brData);
            }

            BlockRecord blockRecordIn = gson.fromJson(brDataBuff.toString(), BlockRecord.class);
            if (!BlockChainTaskToDo.isDuplicate(blockRecordIn))
            {
                BlockChainTaskToDo.bcLedger.add(0, blockRecordIn);
                System.out.println("Block has been added to Ledger");
                System.out.println("Verified Block Count: " + BlockChainTaskToDo.bcLedger.size());

            }
            if (BlockChainTaskToDo.processID == 0){
                BlockChainTaskToDo.writeToJSON();
            }

//            BlockChainTaskToDo.blockchain = brData;
//            System.out.println("         --NEW BLOCKCHAIN--\n" + BlockChainTaskToDo.blockchain + "\n\n");
            bcSocket.close();
        }
        catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }
}
class WorkPuzzle implements Runnable {

    BlockingQueue<BlockRecord> blockQ;
    private static final String alphaNumericStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    public WorkPuzzle(PriorityBlockingQueue<BlockRecord> blockQueue) {
        this.blockQ = blockQueue;
    }

    @Override
    public void run() {
        try {
            while(true) {
                BlockRecord blockRec = BlockChainTaskToDo.blockQueue.take();
                String blockRecStr = blockRec.getBlock_ID() + blockRec.getFirstName() +
                        blockRec.getLastName() + blockRec.getSsnNumber() +
                        blockRec.getDateOfBirth() + blockRec.getMedicalCondition() +
                        blockRec.getTreatmentRec() + blockRec.getMedicineRec() +
                        blockRec.getProcessCreation();
                String concatenateStr = "";
                String hashStr = "";
                boolean isHashVerified;
                boolean isBlockIDVerified;
                if (BlockChainTaskToDo.isDuplicate(blockRec) && blockRec!=null) {
                    System.out.println("Duplicated Block Record in BlockChain");
                    continue;
                }

                isHashVerified = BlockChainTaskToDo.verifySignature(blockRec.getHashMaker().getBytes(),
                        BlockChainTaskToDo.publicKeyList[Integer.valueOf(blockRec.getProcessCreation())],
                        Base64.getDecoder().decode(blockRec.getHashSignedMaker()));

                isBlockIDVerified = BlockChainTaskToDo.verifySignature(blockRec.getBlock_ID().getBytes(),
                        BlockChainTaskToDo.publicKeyList[Integer.valueOf(blockRec.getProcessCreation())],
                        Base64.getDecoder().decode(blockRec.getSignedBlock_ID()));

                String messageHash = isHashVerified ? "Hash Signed" : "Hash not Signed";
                System.out.println(messageHash);

                String messageBlock = isBlockIDVerified ? "Block ID Signed" : "Block ID not Signed";
                System.out.println(messageBlock);

                String randomStr = randomAlphaNumeric(8);
                String previousBlockID = BlockChainTaskToDo.bcLedger.get(0).getBlock_ID();

                int workID = 0;
                String updatedBlock = blockRecStr;
                updatedBlock = updatedBlock + BlockChainTaskToDo.bcLedger.get(0).getWinningHashValue();
                if(!BlockChainTaskToDo.isDuplicate(blockRec) && blockRec!= null) {
                    try {
                        for(int i = 1; i < 10; i++) {
                            randomStr = randomAlphaNumeric(8);
                            concatenateStr = updatedBlock + randomStr;
                            MessageDigest msgDigest = MessageDigest.getInstance("SHA-256");
                            byte[] bytesHash = msgDigest.digest(concatenateStr.getBytes("UTF-8"));

                            hashStr = byteArray2Str(bytesHash);
                            workID = Integer.parseInt(hashStr.substring(0,4),16);

                            if (!(workID < 20000)) {
                                System.out.format("Puzzle not solved! Working again! \n");
                            }

                            if(workID < 20000) {
                                if (previousBlockID != BlockChainTaskToDo.bcLedger.get(0).getBlock_ID()) {
                                    System.out.println("Reading record from Work Loop");
                                    BlockChainTaskToDo.sendBlock2Ledger(blockRec, "reVerifyBlock");

                                }
                                else {
                                    blockRec.setWinningHashValue(hashStr);
                                    blockRec.setRandomSeedValue(randomStr);
                                    System.out.println("Winning Random String being added "+ randomStr);
                                    blockRec.setPreviousHashValue(BlockChainTaskToDo.bcLedger.get(0).getWinningHashValue());

                                    int prevBlockNumber = Integer.valueOf(BlockChainTaskToDo.bcLedger.get(0).getBlockNumber());
                                    prevBlockNumber++;
                                    blockRec.setBlockNumber(String.valueOf(prevBlockNumber));
                                    blockRec.setProcessIDVerification(String.valueOf(BlockChainTaskToDo.processID));

                                    String signHashVerifier = "";

                                    byte[] digitalSign = BlockChainTaskToDo.signData(hashStr.getBytes(),
                                            BlockChainTaskToDo.keysPair.getPrivate());
                                    signHashVerifier=Base64.getEncoder().encodeToString(digitalSign);


                                    blockRec.setWinningSignedHashValue(signHashVerifier);

                                    BlockChainTaskToDo.bcLedger.add(0,blockRec);
                                    System.out.println("BlockRecord added to Blochain Ledger.");
                                    System.out.println("Verified Blocks count is: " + BlockChainTaskToDo.bcLedger.size());
                                    BlockChainTaskToDo.sendBlock2Ledger(blockRec, "bcLedgerUpdate");
                                    continue;
                                }
                                break;
                            }
                            if (BlockChainTaskToDo.isDuplicate(blockRec)){
                                System.out.println("Duplicate block working!");
                                break;
                            }
                            BlockChainTaskToDo.callSleep();
                        }
                    }
                    catch (Exception excpt) {
                        excpt.printStackTrace();
                    }
                    System.out.println("Loop functioning Stopped!");
                }

            }
        } catch (Exception excpt) {
            excpt.printStackTrace();
        }
    }

    public static String randomAlphaNumeric(int count) {
        StringBuilder stringBuilder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random() * alphaNumericStr.length());
            stringBuilder.append(alphaNumericStr.charAt(character));
        }
        return stringBuilder.toString();
    }
    public static String byteArray2Str(byte[] ba2s) {
        StringBuilder hex = new StringBuilder(ba2s.length * 2);
        for(int i=0; i < ba2s.length; i++){
            hex.append(String.format("%02X", ba2s[i]));
        }
        return hex.toString();
    }
}