
import java.math.BigInteger;
import java.security.*;
import java.io.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Date.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

public class Main {
    // 字节转为01比特字符串
    public static String byteToBit(byte b) {
        return "" +(byte)((b >> 7) & 0x1) +
                (byte)((b >> 6) & 0x1) +
                (byte)((b >> 5) & 0x1) +
                (byte)((b >> 4) & 0x1) +
                (byte)((b >> 3) & 0x1) +
                (byte)((b >> 2) & 0x1) +
                (byte)((b >> 1) & 0x1) +
                (byte)((b >> 0) & 0x1);
    }

    // 将字节数组转为0 1 比特字符串
    public static String byteToBitString(byte [] by){
        String res = "";
        for (int i = 0; i < by.length; i++){
            res = res +  byteToBit(by[i]);
        }
        System.out.println(res);
        return res;
    }

    // 将 0 1 比特串转为10进制数字
    public static int BitToTen(String bitStr){
        int num = 0;
        for(int i = 0; i < bitStr.length(); i++){
            if(bitStr.charAt(i) == '0'){
                num = num * 2;
            }
            else{
                num = num * 2 + 1;
            }
        }
        return num;
    }

    //将字节数组转为16进制串
    public static String bytes2hex03(byte[] bytes)
    {
        final String HEX = "0123456789abcdef";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes)
        {
            // 取出这个字节的高4位，然后与0x0f与运算，得到一个0-15之间的数据，通过HEX.charAt(0-15)即为16进制数
            sb.append(HEX.charAt((b >> 4) & 0x0f));
            // 取出这个字节的低位，与0x0f与运算，得到一个0-15之间的数据，通过HEX.charAt(0-15)即为16进制数
            sb.append(HEX.charAt(b & 0x0f));
        }
        return sb.toString();
    }

    // 0 1 字符串转为 16 进制
    public static String bit2Hex(String bitstr){
        char[] DIGITS_LOWER = {'0', '1', '2', '3', '4', '5',
                '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        StringBuilder sb = new StringBuilder(bitstr.length()/4);
        //System.out.println(sb.length());
        for(int i = 0; i < bitstr.length()/4; i++){
            String tmp = bitstr.substring(i * 4, i * 4 + 4);
            int num = 0;
            for(int j = 0; j < 4; j++){
                num = 2 * num + (tmp.charAt(j) - '0');
            }
        //    System.out.println(num);
            sb.append(DIGITS_LOWER[num]);
        }
       // System.out.println(sb);
        return sb.toString().trim();
    }

    // 16进制字符串(长度为2）转为 ansic码
    public static char string2Ansic(String str){
        assert (str.length() == 2);
        int ansic = 0;
      //  System.out.format("ansic %s \n", str);
        HashMap hashmap = new HashMap();
        hashmap.put('0',0);
        hashmap.put('1',1);
        hashmap.put('2',2);
        hashmap.put('3',3);
        hashmap.put('4',4);
        hashmap.put('5',5);
        hashmap.put('6',6);
        hashmap.put('7',7);
        hashmap.put('8',8);
        hashmap.put('9',9);
        hashmap.put('a',10);
        hashmap.put('b',11);
        hashmap.put('c',12);
        hashmap.put('d',13);
        hashmap.put('e',14);
        hashmap.put('f',15);
        ansic = 16 * (int)hashmap.get(str.charAt(0)) +(int) hashmap.get(str.charAt(1));
        return (char)ansic;
    }

    // 将16进制时间格式转为 YY MM DD HH MM SS Z
    public static String UTCTimeToString(String bitStr){
        String timeString = "";
       // System.out.println(bitStr);
        int len = bitStr.length()/2;
        String []timeArr = new String[len];
        for(int i = 0; i < bitStr.length(); i= i+2){
            String tmpStr = bitStr.substring(i, i+2);
            String ansicStr = String.valueOf(((char)string2Ansic(tmpStr)));
            timeArr[i/2] = ansicStr;
          //  System.out.println(i);
        }

        timeString = String.format("UTC time: YY:%s%s/MM:%s%s/DD:%s%s/HH:%s%s/MM:%s%s/SS:%s%s",timeArr[0],timeArr[1],
                timeArr[2],timeArr[3],timeArr[4],timeArr[5],timeArr[6],timeArr[7],
                timeArr[8],timeArr[9],timeArr[10],timeArr[11]);
        return timeString;
    }

    // 将16进制转为对应的OID值。
    public static String BitToOID(String bitStr){
        String oidStr = bitStr;
       // System.out.println("oidStr " + bitStr);
        // 处理一下OID不存在的情况
        HashMap hashmap = new HashMap();
        // 主体 oid
        hashmap.put("550403","CN");
        hashmap.put("550406", "C");
        hashmap.put("55040a", "O");
        hashmap.put("55040b", "OU");
        // 算法oid
        hashmap.put("2a8648ce380401", "DSA");
        hashmap.put("2a8648ce380403" ,"sha1DSA" );
        hashmap.put("2a864886f70d010101" ,"RSA");
        hashmap.put("2a864886f70d010102","MD2RSA");
        hashmap.put("2a864886f70d010103", "MD4RSA");
        hashmap.put("2a864886f70d010104", "MD5RSA");
        hashmap.put("2a864886f70d010105", "sha1RSA");
        // 扩展oid
        hashmap.put("551d01", "May be a temp extension");
        hashmap.put("551d09", "SybjectDirectoryAttributes");
        hashmap.put("551d23","Authority key indentifier");
        hashmap.put("551d0e", "subjectKeyIndentifier");
        hashmap.put("551d0f", "keyUsage" );
        hashmap.put("551d1f", "CRLDIstributionPoints");
        hashmap.put("551d21","subjectAltName");
        hashmap.put("551d23", "AuthorityKeyIdentifier");
        hashmap.put("551d20","certificate polices");
        hashmap.put("551d10", "privatekeyusageperiod");
        hashmap.put("551d11", "sybjectAlternativeName");
        hashmap.put("551d13", "basicconstraint");
        hashmap.put("551d12","issuerAltName" );
        if(hashmap.get(oidStr) == null){
            return "unknown";
        }
        return (String)hashmap.get(oidStr);
    }

    // oid分为三类，主体oid，算法oid，扩展oid
    public static int getOIDType(String oidStr){
       // System.out.format("get oid: oidstr %s\n", oidStr);
        String [][] oidSet = {{"550403", "550406","55040a","55040b" },
                {"2a8648ce380401","2a8648ce380403","2a864886f70d010101",
                        "2a864886f70d010102","2a864886f70d010103",
                        "2a864886f70d010104","2a864886f70d010105"},
                {"551d01","551d09","551d23","551d0e","551d0f","551d1f",
                        "551d21","551d23","551d20","551d10","551d11",
                        "551d13","551d12" }
        };
        for(int i = 0; i < oidSet.length; i++){
            for(int j = 0; j < oidSet[i].length; j++){
                if (oidSet[i][j].equals(oidStr)){
                    return i;
                }
            }
        }
        return -1;
    }

    // 将printable类型的16进制数据转为text文本
    public static String printStr2text(String printStr){
        assert (printStr.length()%8 == 0);
        String text = "";
        String hexStr = printStr;
       // System.out.println(printStr);
        for(int i = 0; i < hexStr.length(); i = i +2){
            String tmpStr = printStr.substring(i, i+2);
            char res = (char)string2Ansic(tmpStr);
            text += res;
        }
        return text;
    }
    // 将文件字节流转为字节数组
    public static byte[] FiletoByteArray(String filename) throws IOException{
        byte[] by = {0};
        try{
            File f=new File(filename);
            FileInputStream fis=new FileInputStream(f);
            int size = fis.available(); // 返回输入流中可以被读的bytes字节估量值
            DataInputStream dis=new DataInputStream(fis);
            by=new byte[size];//要读取的位数(一次性全部读取
            dis.read(by);
            return by;
        }
        catch (Exception e){
            e.printStackTrace();
        }
        return by;
    }

        // 分析01比特串 解析证书信息, 假设证书内部信息都为定长
    private static void readX_509ByMyself(String certificatefile)throws IOException{

            // 读取证书文件，转为字节数组
            byte [] byteCer = FiletoByteArray(certificatefile);
            //  字节数组转为 0 1 比特字符串
            String bitStringCer = byteToBitString(byteCer);

            // 开始分析比特串
            int index = 0;  // 用于判断字符串解析位置
            int start = 0;
            int end = 7;
            int byteNum = bitStringCer.length()/8;  // 总字节数
            int byteIndex = 0;
          //  System.out.println(byteNum);
          //  System.out.println(bitStringCer.length());


            Integer[]  integerArr = new Integer[30] ;      // 存储integer
            int intIndex = 0;
            String [] bigIntegerArr = new String[30]; // 存储证书拥有的bigInteger
            int BigIntIndex = 0;
            String [] bitStringArr = new String[30];     // 存储位串
            int bitStringIndex = 0;
            String [] printableStringArr = new String[30];//  存储打印的信息串
            int printableStringIndex = 0;
            String [] timeArr = new String[30];          // 存储UTC 时间
            int timeIndex = 0;
            String []subjectOidStringArr = new String[30];  // 存储 主体信息OID
            String[] subjectStringArr = new String[30];  // 存储主体信息内容
            int subjectStringIndex = 0;


            String [] oidStringArr  = new String[30];       //  存储OID
            int oidStringIndex = 0;

            String [] algorithmOIDArr = new String[30];
            int algorithmOIDIndex = 0;
            String oidKeyString = "";                    // 存储签名算法oid
            int exponent = 1;

            String [] expandOIDArr = new String[30];  // 存储扩展字段oid
            int expandOIDIndex = 0;
            String [] expandArr = new String[30]; // 存储扩展字段
            int expandIndex = 0;
            String [] octetStringArr = new String[30]; // 存储多字节
            int octetStringIndex = 0;

            int cerVersion = 0;
            String issuerUniqueID = "";
            String subjectUniqueID = "";
            // 将数据块内容存储在数组中
            boolean [] boolArr = new boolean[10];         // 存储bool类型
            int boolIndex = 0;

            String [] unknownStrArr = new String[100];
            int unknownIndex = 0;     // 存放未解析字段

        while(start != bitStringCer.length()){

                System.out.println("----开始分析---------------------");
                // 分析数据标识类型 //////////////////////////////////////////////////////////////]

                String dataSign = bitStringCer.substring(start, start + 8);  // 数据块头部标识 一个字节
                System.out.format("1 获取比特串start : %d, end: %d\n", start, start + 8);
                System.out.format("1 更新比特串start : %d\n",start + 8);
                System.out.println("dataSign-part: " + dataSign + " hex: " + bit2Hex(dataSign));
                start = start + 8;  // 更新start
                String bit87 = dataSign.substring(0,2);   // 用来标识TAG，有四种类型

                int bit51 = 0;  // 记录 bit5 - bit1的10进制
                bit51 = BitToTen(dataSign.substring(3, 8)); // 获取bit5- 1的数字

                // 分析数据块长度////////////////////////////////////////////////
                String dataLength = bitStringCer.substring(start , start + 8); // 取数据块长度 第一个字节
                System.out.format("2 获取比特串start : %d, end: %d\n", start, start + 8);
                System.out.format("2 更新比特串start : %d\n",start + 8);
                System.out.println("dataLength-part: " + dataLength + " hex:" + bit2Hex(dataLength));
                start = start + 8;  // 更新start
                char bit8 = dataLength.charAt(0);
                int length = 0;  //数据块长度值
                if(bit8 == '0'){
                    // 长度值小于4 个字节
                    length = BitToTen(dataLength.substring(1,8)); //获取数据块长度
                    System.out.format("data length = %d < 127\n", length);
                }
                else if(bit8 == '1'){
                    //  长度值大于127
                    int byteLen = BitToTen(dataLength.substring(1, 8)); // 得到实际的字节数，用来表示长度值
                   // System.out.format("data byte num is %d, start : %d, end: %d\n", byteLen, start, start + 8);
                    length = BitToTen(bitStringCer.substring(start,  start + 8 * byteLen));  // 获取数据块长度
                    System.out.format("3 获取比特串start : %d, end: %d\n", start, start + 8 * byteLen);
                    System.out.format("3 更新比特串start : %d\n",start + 8*byteLen);
                    System.out.format("data length = %d > 127 hex : %s\n" ,length, bit2Hex(bitStringCer.substring(start,  start + 8 * byteLen)));
                    start = start + 8 * byteLen;  // 更新start
                }
                else if(dataLength == "10000000"){
                    // 数据块长度补丁，由数据块结束标识字段（0x0000)结束数据块
                    length = -1;
                }

                // 根据数据类型和数据块长度分析数据块，获取数据,然后更新start//////////////////////////////////
                if(length == -1){
                    System.out.println("跳过变长字段。");
                    while(true){
                        if(bitStringCer.substring(start, start + 16) == "0000000000000000"){
                            System.out.format("4 获取比特串start : %d, end: %d\n", start, start + 16);
                            System.out.format("4 更新比特串start : %d\n",start + 16);
                            start = start + 16;
                            break;
                        }
                        start++;
                    }
                    continue; // 假设证书数据都是定长的数据段
                }

                System.out.format("bit87: %s  bit51: %d\n", bit87, bit51);
                if(bit87.charAt(0) == '0' && bit87.charAt(1) == '0' && bit51 == 16 ){
                    System.out.format("----- 跳过sequence 字段\n");
                    continue;
                }
                if(bit87.charAt(0) == '0' && bit87.charAt(1) == '0' && bit51 == 17 ){
                    System.out.format("----- 跳过set字段\n");
                    continue;
                }
                if(bit87.charAt(0) == '1' && bit87.charAt(1) == '0' && bit51 == 0){
                    System.out.format(("------ 跳过version字段\n"));
                    continue;
                }
                if(bit87.charAt(0) == '1' && bit87.charAt(1) == '0' && bit51 == 3){
                    System.out.format(("------ 扩展字段\n"));
                 //   continue;
                }

              //  System.out.format("bit87%sbit51 %d\n", bit87, bit51);
                int endBound = 0;  // 防止越界
                if(start + 8 *length < bitStringCer.length()){
                    endBound = start + 8 * length;
                }
                else {
                    endBound = bitStringCer.length();
                }
                String dataBlock = bitStringCer.substring(start, endBound); // 获取数据块
                System.out.format("4 获取比特串start : %d, end: %d\n", start, endBound);
                System.out.format("4 更新比特串start : %d\n",endBound);
                start = endBound;  // 更新start位置
                System.out.println("dataBlock: " + bit2Hex(dataBlock));
                System.out.format("bit87: %s  bit51: %d\n", bit87, bit51);
                if(bit87.charAt(0) == '0' && bit87.charAt(1) == '0'){
                    if(bit51 == 1){
                        // boolean
                        System.out.println("data type:  boolean.");
                        if(dataBlock == "11111111")
                            boolArr[boolIndex++] = true;
                        if(dataBlock == "00000000")
                            boolArr[boolIndex++] = false;
                    }
                    else if(bit51 == 2){
                        // integer
                        System.out.format("data type:  integer. %s\n", bit2Hex(dataBlock));
                        if(dataBlock.length() < 10)
                            integerArr[intIndex++] = BitToTen(dataBlock);
                        else
                            bigIntegerArr[BigIntIndex++] =  bit2Hex(dataBlock);
                    }
                    else if(bit51 == 3){
                        // bit string
                        System.out.println("data type:  bit string.");
                        bitStringArr[bitStringIndex++] = bit2Hex(dataBlock);
                    }
                    else if(bit51 == 4){
                        //octet string
                        System.out.println("data type:  octet string.");
                        octetStringArr[octetStringIndex++] =bit2Hex(dataBlock);
                    }
                    else if(bit51 == 5){
                        System.out.println("data type: null");
                    }
                    else if(bit51 == 6){
                        // oid
                        int type = getOIDType(bit2Hex(dataBlock));
                        if(type == 0){
                            subjectOidStringArr[subjectStringIndex++] = bit2Hex(dataBlock);
                            System.out.format("data type:  subject oid. %s\n", bit2Hex(dataBlock));
                        }
                        else if(type == 1){
                            algorithmOIDArr[algorithmOIDIndex++] = bit2Hex(dataBlock);
                            System.out.format("data type: algorithm oid. %s\n", bit2Hex(dataBlock));
                        }
                        else if(type == 2){
                            expandOIDArr[expandOIDIndex++] = bit2Hex(dataBlock);
                            System.out.format("data type: expand oid. %s\n", bit2Hex(dataBlock));
                        }
                        else if(type == -1){
                            unknownStrArr[unknownIndex++] = bit2Hex(dataBlock);
                            System.out.format("data type: unknown oid. %s--------------------------------\n", bit2Hex(dataBlock));
                        }
                        oidStringArr[oidStringIndex++] = bit2Hex(dataBlock);
                        System.out.format("data type:oid. %s\n", bit2Hex(dataBlock));

                    }
                    else if(bit51 == 16){
                        // sequence  pass
                        System.out.println("data type:  sequence.");
                    }
                    else if(bit51 == 17){
                        System.out.println("data type:  set.");
                        // set pass
                    }
                    else if(bit51 == 19){
                        // printable string
                        printableStringArr[printableStringIndex++] = bit2Hex(dataBlock);
                        System.out.println("data type: printable string.");
                    }
                    else if(bit51 == 23){
                        // UTC time
                        timeArr[timeIndex++] = bit2Hex(dataBlock);
                       // System.out.println("data type:  UTC time.");
                        if(timeIndex == 1){
                            System.out.println("Get the notBefore time.");
                        }
                        else if(timeIndex == 2){
                            System.out.println("Get the not after time.");
                        }
                    }
                    else{
                        System.out.format("Unknown data type. bit51 = %d -----------------------\n", bit51);
                        unknownStrArr[unknownIndex++] = bit2Hex(dataBlock);
                    }
                }
                else if(bit87.charAt(0) == '1' && bit87.charAt(1) == '0'){
                    if(bit51 == 0){
                        // 证书的版本
                        cerVersion = BitToTen(dataBlock);
                        System.out.format("data-type: version %d.\n ", cerVersion);
                    }
                    if(bit51 == 1){
                        // issuer 唯一id
                        issuerUniqueID = bit2Hex(dataBlock);
                        System.out.format("data-type: issueruniqueID. %s\n", issuerUniqueID);
                    }
                    if(bit51 == 2){
                        // 证书主体唯一id  subjectUniqueID
                        subjectUniqueID = bit2Hex(dataBlock);
                        System.out.format("data-type: subjectUniqueID. %s\n", subjectUniqueID);
                    }
                    if(bit51 == 3){
                        // 证书的扩展字段
                        expandArr[expandIndex++] =bit2Hex(dataBlock);
                        System.out.format("data-type: expand part.\n");
                    }
                }
            }
            System.out.println("Boolean data:");

        for(int i = 0; i < boolIndex; i++){
            System.out.println(boolArr[i]);
        }
        System.out.println("integer data:");
        for(int i = 0; i < intIndex; i++){
            System.out.println(integerArr[i]);
        }
        System.out.println("big integer data:");
        for(int i = 0; i < BigIntIndex; i++){
            System.out.println(bigIntegerArr[i]);
        }
        System.out.println("bit string data:");
        for(int i = 0; i < bitStringIndex; i++){
            System.out.println(bitStringArr[i]);
        }
        System.out.println("time data:");
        for(int i = 0; i < timeIndex; i++){
            System.out.println(timeArr[i]);
        }
        System.out.println("octet string data:");
        for(int i = 0; i < octetStringIndex; i++){
            System.out.println(octetStringArr[i]);
        }
        System.out.println("oid data:");
        for(int i =0; i < oidStringIndex; i++){
            System.out.println(oidStringArr[i]);
        }
        System.out.println("printable string data:");
        for(int i = 0; i < printableStringIndex; i++){
            System.out.println(printableStringArr[i]);
        }
        System.out.println("expand data:");
        for(int i = 0; i < expandIndex; i++){
            System.out.println(expandArr[i]);
        }
        System.out.println("unknown:");
        for(int i = 0; i < unknownIndex; i++){
            System.out.println(unknownStrArr[i]);
        }

        System.out.println("输出证书读取结果");
        System.out.println("---------\n证书主体部分:");
        System.out.format("主体唯一ID：");
        System.out.println(issuerUniqueID);
        System.out.format("issuer唯一ID：");
        System.out.println(issuerUniqueID);
        System.out.format("证书版本号：%d\n", integerArr[0] + 1 );
        System.out.format("证书序列号：%s\n", bigIntegerArr[0]);
        System.out.format("证书签名值：%s\n",bitStringArr[0]);
        System.out.format("主体: \n");
        for(int i = 0; i < printableStringIndex; i++){
            System.out.format("%s = %s ", BitToOID(subjectOidStringArr[i]), printStr2text(printableStringArr[i]));
        }
        System.out.format("\n有效期：从 %s 到 %s \n",  UTCTimeToString(timeArr[0]), UTCTimeToString(timeArr[1]));
        System.out.println("---------\n证书签名算法标识:");
        System.out.format("签名算法：%s\n", BitToOID(algorithmOIDArr[0]));
        System.out.format("module: %s\n", bitStringArr[1]);
        System.out.format("exponent: %d\n", exponent);
        System.out.println("----------\n证书扩展部分:");
        for(int i = 0; i < expandIndex; i++){
            System.out.format("OID:%s 内容：%s, octstring: %s", BitToOID(expandOIDArr[i]), expandArr[i], octetStringArr[i]);
        }
        System.out.println("----------\n未知部分:");
        for(int i = 0; i < unknownIndex; i++){
            System.out.format("%s \n", unknownStrArr[i]);
        }
    }



    // 使用自带库函数读取X.509证书
    private static void readX_509(String certificateName){
        try{
            CertificateFactory CF = CertificateFactory.getInstance("X.509"); // 从证书工厂中获取X.509的单例类
            FileInputStream fileIn = new FileInputStream(certificateName); // 将证书读入文件流
            Certificate C = CF.generateCertificate(fileIn);  // 将文件流的证书转化为证书类
            String  certificateStr = C.toString();
            System.out.println("使用[自带库函数]读入证书结果如下：");
            System.out.print(certificateStr);
            System.out.println("--------------------------------------\n证书主要字段:");
            X509Certificate cer = (X509Certificate)C;
            System.out.println("版本号：" + cer.getVersion());
            System.out.println("序列号：" + cer.getSerialNumber().toString());
            System.out.println("颁发者：" + cer.getSubjectDN());
           // System.out.println("颁发者唯一标识符: " + cer.getSubjectUniqueID().toString());
            System.out.println("使用者：" + cer.getIssuerDN());
          //  System.out.println("使用者唯一标识符: " + cer.getIssuerUniqueID().toString());
            System.out.println("有效期：from：" + cer.getNotBefore() + "  to: " + cer.getNotAfter());
            System.out.println("签发算法" + cer.getSigAlgName());
            System.out.println("签发算法ID：" + cer.getSigAlgOID());
            System.out.println("证书签名:" + cer.getSignature().toString());
            byte [] sig = cer.getSigAlgParams();
            PublicKey pk = cer.getPublicKey();
            byte [] pkenc = pk.getEncoded();
            System.out.println("公钥：");
            for(int i = 0; i < pkenc.length; i++){
                System.out.print(pkenc[i]);
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }


    public static void main(String[] args) throws IOException{
         readX_509ByMyself("myCA.cer");
         readX_509("myCA.cer");
         readX_509ByMyself("pixiv.cer");
        readX_509("pixiv.cer");
    }
}
