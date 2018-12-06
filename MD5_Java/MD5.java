/*****************************************
 *  Function：实现MD5消息摘要算法
 *  Author：  Qiu Yihao
 *  Date：    2018-12-04
 *  Contact:  576261090@qq.com
 *****************************************/

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.*;
import java.lang.*;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;


public class Main {
    static byte[] M;                  /* 存放消息字节数组 */

    static long[] T = new long[64];   /* 迭代运算的T表， 64个元素，每个元素有32bits，16进制8位 */

    /*在迭代中的消息数组*/
    static long[] X = new long[16];

    /*四个寄存器A，B，C，D，构成128bits的迭代缓冲区*/
    static long A = 0x67452301;
    static long B = 0xEFCDAB89;
    static long C = 0x98BADCFE;
    static long D = 0x10325476;

    /*四个临时寄存器*/
    static long tmpA;
    static long tmpB;
    static long tmpC;
    static long tmpD;

    /* *
     *  @ param  x  被移数
     *  @ param  s  左移的位数
     * */
    public static long rotate_left(long x, long s){
        return ((x) << (s))| ((x) >>> (32 - s)) & 0xFFFFFFFFL;
    }

    public static long encode(long t){
        return ((t >> 24) & 0xff) | ((t >> 16) & 0xff) << 8 | ((t >> 8) & 0xff) << 16 | (t & 0xff) << 24;
    }

    /*四重循环使用的函数*/
    /*
    * @param a b c d 为四个缓冲区的内容
    *        k 为X[k]
    *        s 为移位数目
    *        i为 T[j]
     */
    public static long F_Func(long a,long b,long c,long d,long k,long s, long i){
        return (b + rotate_left(((a + ((b & c) | ((~b) & d)) + k + i) & 0xFFFFFFFFL),s)) & 0xFFFFFFFFL;
    }

    public static long G_Func(long a,long b,long c,long d,long k,long s, long i){
        return (b + rotate_left(((a + ((b & d) | (c & (~d))) + k + i) & 0xFFFFFFFFL),s)) & 0xFFFFFFFFL;
    }

    public static long H_Func(long a,long b,long c,long d,long k,long s, long i){
        return (b + rotate_left(((a + (b ^ c ^ d) + k + i) & 0xFFFFFFFFL) , s)) & 0xFFFFFFFFL;
    }

    public static long I_Func(long a,long b,long c,long d,long k,long s, long i){
        return (b + rotate_left(((a + (c ^ (b | (~d))) + k + i) & 0xFFFFFFFFL), s)) & 0xFFFFFFFFL;
    }

    /*将long类型转化为字节数组*/
    public static byte[] longToByteArray(long value) {
        return new byte[] {
                (byte) (value),
                (byte) (value >> 8),
                (byte) (value >> 16),
                (byte) (value >> 24),
                (byte) (value >> 32),
                (byte) (value >> 40),
                (byte) (value >> 48),
                (byte) (value >> 56)
        };
    }

    /*生成迭代的T表格*/
    public static void create_T_Table(){
        for(int i = 0;i < 64;i++){
            T[i] = (long) (Math.floor(Math.abs(Math.sin(i+1)) * (long)Math.pow(2,32)));
        }
    }



    public static  void getMD5ByFile(String inputString){

        long length = 0;         // 原始消息的长度
        int paddingLength = 0;   // 尾部填充长度

        byte [] pad;    // 字节流面板

        File file = new File(inputString);  // 文件操作对象
        length = file.length();             // 获取文件的字节长度1

        // 获取填充的位数
        if(length % 64 < 56){
            paddingLength = (int)(56 - length % 64); // 字节
        }
        else if(length % 64 == 56){
            paddingLength = 64;   // 64 字节
        }
        else if(length % 64 > 56){
            paddingLength = (int) (64 - (length % 64 - 56));
        }

        try{
            System.out.format("开始读取文件 %s\n", inputString);
            FileInputStream fis = new FileInputStream(inputString);   // 读入文件流
            BufferedInputStream bis = new BufferedInputStream(fis);   // 将文件流读入缓冲区
            DataInputStream dis = new DataInputStream(bis);           // 将缓冲区数据写入数据流

            M = new byte[(int) (length + paddingLength + 8)];     // 填充消息最终长度  满足于 length + padding + 8 = 0 mod 64  字节
            System.out.println("消息内容读取成功！");
            // 将文件内容读入全部字节数组M中并填充
            for(int i = 0; i < length + paddingLength; i++){
                if( i < length){
                    M[i] = (byte)dis.read();
                }
                else if(i == length){
                    M[i] = (byte)128;
                }
                else{
                    M[i] = 0;
                }
            }

            pad  = longToByteArray(length * 8 );

            // 消息尾部附加K值的低8个字节， 64位
            for(int i = 0; i < 8; i++){
                M[(int)(i + length + paddingLength)] = (byte) pad[i];
            }
            System.out.println("消息填充成功！");
            create_T_Table();  // 生成T表



            // 该循环的作用是：对全部原始消息进行分块，每块大小为64个字节，共512位
            System.out.println("开始循环压缩消息！");
            int j = 0;
            int k = 0;
            int i = 0;
            int div16 = 0;
            int g = 0;
            for(i=0;i<(length+paddingLength + 8)/64;i++)
            {
                for(j=0,k=0;j<16;j++,k+=4){
                    X[j] = ((int)M[i*64 + k] & 0xFF) | ((int)M[i*64+k+1] & 0xFF) << 8 | ((int)M[i*64+k+2] & 0xFF) << 16 | ((int)M[i*64+k+3] & 0xFF) << 24;
                }
                long temp_A = A;
                long temp_B = B;
                long temp_C = C;
                long temp_D = D;

                for (j = 0; j < 64; j++)
                {
                    div16 = j >>> 4;

                    switch (div16)
                    {
                        case 0:
                            g = j;
                            if(j % 4 == 0)
                            {
                                A = F_Func(A,B,C,D,X[g],7,T[j]);
                            }
                            else if(j % 4 == 1)
                            {
                                D = F_Func(D,A,B,C,X[g],12,T[j]);
                            }
                            else if(j % 4 == 2)
                            {
                                C = F_Func(C,D,A,B,X[g],17,T[j]);
                            }
                            else if(j % 4 == 3)
                            {
                                B = F_Func(B,C,D,A,X[g],22,T[j]);
                            }
                            break;
                        case 1:
                            g = (j * 5 + 1) % 16;
                            if(j % 4 == 0)
                            {
                                A = G_Func(A,B,C,D,X[g],5,T[j]);
                            }
                            else if(j % 4 == 1)
                            {
                                D = G_Func(D,A,B,C,X[g],9,T[j]);
                            }
                            else if(j % 4 == 2)
                            {
                                C = G_Func(C,D,A,B,X[g],14,T[j]);
                            }
                            else if(j % 4 == 3)
                            {
                                B = G_Func(B,C,D,A,X[g],20,T[j]);
                            }
                            break;
                        case 2:
                            g = (j * 3 + 5) % 16;
                            if(j % 4 == 0)
                            {
                                A = H_Func(A,B,C,D,X[g],4,T[j]);
                            }
                            else if(j % 4 == 1)
                            {
                                D = H_Func(D,A,B,C,X[g],11,T[j]);
                            }
                            else if(j % 4 == 2)
                            {
                                C = H_Func(C,D,A,B,X[g],16,T[j]);
                            }
                            else if(j % 4 == 3)
                            {
                                B = H_Func(B,C,D,A,X[g],23,T[j]);
                            }
                            break;

                        case 3:
                            g = (j * 7) % 16;
                            if(j % 4 == 0)
                            {
                                A = I_Func(A,B,C,D,X[g],6,T[j]);
                            }
                            else if(j % 4 == 1)
                            {
                                D = I_Func(D,A,B,C,X[g],10,T[j]);
                            }
                            else if(j % 4 == 2)
                            {
                                C = I_Func(C,D,A,B,X[g],15,T[j]);
                            }
                            else if(j % 4 == 3)
                            {
                                B = I_Func(B,C,D,A,X[g],21,T[j]);
                            }
                            break;
                    }
                }
                A = (A + temp_A) & 0xFFFFFFFFL;
                B = (B + temp_B) & 0xFFFFFFFFL;
                C = (C + temp_C) & 0xFFFFFFFFL;
                D = (D + temp_D) & 0xFFFFFFFFL;

            }
            System.out.println("消息压缩结束！");

            A = encode(A);   // 转为大端形式
            B = encode(B);
            C = encode(C);
            D = encode(D);
            System.out.format("MD5：\n%x%x%x%x\n",A,B,C,D);
            fis.close();
            bis.close();
            dis.close();
        }
        catch(IOException e){
            System.out.println("There is no such an file.");
        }
    }




    /*调用java自带md5函数 输出md5值*/
    public static String getMd5ForFile(String fileName) throws IOException, NoSuchAlgorithmException {
        FileInputStream in = null;
        File file = new File(fileName);
        in = new FileInputStream(file);
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        byte[] cache = new byte[2048];
        int len;
        while ((len = in.read(cache)) != -1) {
            md5.update(cache, 0, len);
        }
        in.close();
        BigInteger bigInt = new BigInteger(1, md5.digest());
        return bigInt.toString(16);
    }

    public static void main(String[] args)throws IOException,  NoSuchAlgorithmException{
        String inputString = "";       // 输入的文件名
        System.out.println("输入加密的文件名：");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        inputString = br.readLine();//直接读取字符串
        getMD5ByFile(inputString);  // 自行实现的函数
        System.out.println("java自带的MD5函数结果如下:");
        System.out.println(getMd5ForFile(inputString));  // 使用java自带的MD5函数
    }
}
