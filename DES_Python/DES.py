"""
    Autor: qiuyh 16340186 

    contact: 576261090@qq.com

    Date: 18/11/1
    
    Description: achieve an encryption algoriithm -- DES(Data Encryption Standard)

    Note: To code a nice code !
"""

import numpy 
import random

#########文件变量
CIPHER_TEXT_FILE = "cipherText.txt"   #密文文件
PLAIN_TEXT_FILE = "plainText.txt"     #明文文件
SECRET_KEY_FILE = "secretKey.txt"     #密钥文件
DECRYPT_TEXT_FILE = "decryptText.txt" #解密文件

######## 显示过程变量,为真显示加密步骤
PRINT_FLAG = True

########异或运算###################################################################################
"""
    function:do XOR operation on bits string s1, s2  异或运算
    condition: len (s1) == len(s2)
    return: xorResult -- the xor result and itstype is list
"""
def XOROperation(s1,s2):
    length = len(s1)     
    xorResult = []
    for i in range(0, length):
        # 转为int类型0，1比特，进行异或操作后，转为string类型
        xorResult.extend(str(int(s1[i]) ^ int(s2[i])))
    return xorResult
####################################################################################################


########## int 转 二进制 指定位数#####################################################################
def int2bin(n, count=24):
    """returns the binary of integer n, using count number of digits"""
    return "".join([str((n >> y) & 1) for y in range(count-1, -1, -1)])
######################################################################################################


######表格置换函数###################################################################################
"""
    function: transfrom the binaryStr with the giver permutation table
    condition: len(binaryStr) == len(PermutationTable)
    return: the permutated binary List.
"""

def Permutation(binaryStr, PermutationTable):
    length = len(PermutationTable)
    PermutatedList = []
    for i in range(0, length):
        PermutatedList.extend(binaryStr[PermutationTable[i] - 1])
    return PermutatedList
####################################################################################################





##循环左移############################################################################################
"""
    function: to achieve cycle shift n bits.
    return: the shifted result.
"""
def shiftLeft(binaryStr, nBits):
    length = len(binaryStr)
    nBits = nBits % nBits
    shiftedList = list(binaryStr)
    for i in range(0, length):
        if i < nBits:
            shiftedList.extend(shiftedList[0])
            del shiftedList[0]
        else:
            break
    return shiftedList
####################################################################################################





##字节转比特#########################################################################################
def ByteToBit(ByteString):
    bitList = []
    for i in range(0,4):
        bitList.insert(0, str(ByteString%2))
        ByteString = int(ByteString / 2)
    bitResult = "".join(bitList)
    return bitResult
####################################################################################################





#########初始P置换####################################################################################
InitialPermutationTable=[58,50,42,34,26,18,10,2,
                        60,52,44,36,28,20,12,4,
                        62,54,46,38,30,22,14,6,
                        64,56,48,40,32,24,16,8,
                        57,49,41,33,25,17,9,1,
                        59,51,43,35,27,19,11,3,
                        61,53,45,37,29,21,13,5,
                        63,55,47,39,31,23,15,7]

"""
    function: Initial permutation function
    input: M_0--64bit plain text block
    return: L_0--the front 32 bits of M_0 , R0--the back 32 bits of M_0
"""
def InitialPermutation(M_0):
    if PRINT_FLAG == True: 
        print("> 进行初始IP置换")
    InitialPermutationResult = Permutation(M_0, InitialPermutationTable)
    L_0 = InitialPermutationResult[0:int((len(InitialPermutationResult)/2))]
    R_0 = InitialPermutationResult[int((len(InitialPermutationResult)/2)):int(len(InitialPermutationResult))]
    return L_0, R_0 # List type
##############################################################################################





#####PC-1置换#########################################################################################
PC_1Table = [57,49,41,33,25,17,9,
            1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,
            19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,
            7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,
            21,13,5,28,20,12,4]

"""
    function: PC-1 permutation
    input: 56 not checked bits of secret ley
    return: C_0, D_0 
"""
def PC_1_Permutation(SecretKey):
    if PRINT_FLAG == True: 
        print("> 进行PC-1 置换")
    PC_1_PermutationResult = Permutation(SecretKey, PC_1Table)
    C_0 = PC_1_PermutationResult[0: int(len(PC_1_PermutationResult)/2)]
    D_0 = PC_1_PermutationResult[int(len(PC_1_PermutationResult)/2): int(len(PC_1_PermutationResult))]
    return C_0, D_0
##############################################################################################





########循环左移函数######################################################################################
"""
    function: do ring shift left on a str_28_bits
    input: str_28_bits -- a 28 bits string; ShiftFlag -- when it is 1,2,9,16, shift 2 bits
    return: shift_result
"""
def RingShiftLeft(str_28_bits, ShiftFlag):
    shiftResult = ""
    if ShiftFlag == 1 or ShiftFlag == 2 or ShiftFlag == 9 or ShiftFlag == 16:
        shiftResult = shiftLeft(str_28_bits, 2)
    else:
        shiftResult = shiftLeft(str_28_bits, 1)
    return shiftResult
##############################################################################################





##########PC-2置换####################################################################################
PC_2Table = [14,17,11,24,1,5,
            3,28,15,6,21,10,
            23,19,12,4,26,8,
            16,7,27,20,13,2,
            41,52,31,37,47,55,
            30,40,51,45,33,48,
            44,49,39,56,34,53,
            46,42,50,36,29,32]
"""
    function: PC-2 compressed permutation
    input:  str_56_bits
    return: str_48_bits
"""
def PC_2_Permutation(str_56_bits):
    if PRINT_FLAG == True: 
        print("> 进行PC-2置换")
    #  去掉9， 18， 22， 25， 35， 38，43， 54 位
    str_48_bits = Permutation(str_56_bits, PC_2Table)
    return str_48_bits
##############################################################################################





####创建子密钥##################################################################################
"""
    function: create the 16 son keys with the given key
    return: sonKeysList: 16 son keys list
"""
def createSonKey(SecretKey):
    # 提取密钥中的非校验位
    if PRINT_FLAG == True: 
        print("> 正在生成16个子密钥")
    str_56_bits_List = list(SecretKey)
    sonKeyList = []
    # 获取子密钥
    Temp_PC_1_PermutationResult_C_i_1, Temp_PC_1_PermutationResult_D_i_1 = PC_1_Permutation(str_56_bits_List) 
    C_i = []
    D_i = []     
    for i in range(1, 17):        
        # C_i-1 D_i-1
        # 计算C_i D_i
        if i == 1 or i == 2 or i == 9 or i == 16:
            C_i = shiftLeft(Temp_PC_1_PermutationResult_C_i_1, 1)
            D_i = shiftLeft(Temp_PC_1_PermutationResult_D_i_1, 1)
        else:
            C_i = shiftLeft(Temp_PC_1_PermutationResult_C_i_1, 2)
            D_i = shiftLeft(Temp_PC_1_PermutationResult_D_i_1, 2)
        CD = C_i + D_i
        sonKey_i = PC_2_Permutation(CD)
        sonKeyList.append(sonKey_i)  
        Temp_PC_1_PermutationResult_C_i_1 = C_i
        Temp_PC_1_PermutationResult_D_i_1 = D_i
        if i == 16:
            break
    return sonKeyList
##############################################################################################





######E扩展置换#################################################################################
E_ExpandTable = [32,1,2,3,4,5,
                4,5,6,7,8,9,
                8,9,10,11,12,13,
                12,13,14,15,16,17,
                16,17,18,19,20,21,
                20,21,22,23,24,25,
                24,25,26,27,28,29,
                28,29,30,31,32,1]
"""
    function: E_Expand on the 32 bits R(i-1) string
    input: R_i_1 -- the (i-1)th back 32 bits string
    return: E_R_i_1 -- the 48 bits expanded string
"""
def E_Expand(R_i_1):
    if PRINT_FLAG == True: 
        print("> 正在进行E扩展置换")
    E_R_i_1 = Permutation(R_i_1, E_ExpandTable)
    return E_R_i_1
##############################################################################################





#######S盒置换################################################################################
eight_S_Boxes=[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
                0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
                4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
                15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,],
                [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
                3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
                0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
                13,8,10,1,3,15,4,2,11,6,7,12,10,5,14,9,],
                [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
                13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
                13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
                1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
                [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
                13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
                10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
                3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,],
                [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
                14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
                4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
                11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
                [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
                10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
                9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
                4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,],
                [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
                13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
                1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
                6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
                [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
                1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
                7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
                2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
"""
    function: to transfrom a 6-bits string to a 4-bits string with 8 S-Boxes
    input: six_bits_str -- 6-bits string; S_Box_Num -- indicate the number of the S-Box [1, 8]
    return: four_bits_str -- 4 bits string group
"""
def S_Box_Transformation(six_bits_str, S_Box_Num):
    if PRINT_FLAG == True: 
        print("> 正在通过S盒进行6-4转换")
    row = int(six_bits_str[0]) * 2 + int(six_bits_str[5])
    col = int(six_bits_str[1]) * 8 + int(six_bits_str[2]) * 4 + int(six_bits_str[3]) * 2 + int(six_bits_str[4])
    value = eight_S_Boxes[int(S_Box_Num - 1)][int(row * 15 + col)]
    four_bits_str = list(int2bin(value,4))
    return four_bits_str
##############################################################################################





########P扩展置换##############################################################################
P_Table=[16,7,20,21,
   29,12,28,17,
   1,15,23,26,
   5,18,31,10,
   2,8,24,14,
   32,27,3,9,
   19,13,30,6,
   22,11,4,25]
"""
    function: P_Permutation on the 32 bits string
    input: str_32bits -- the 32 bits string List
    return: FeistelResult -- the output of the feistel function
"""
def P_Permutation(str_32bits):
    if PRINT_FLAG == True: 
        print("> 正在进行P置换")
    FeistelResult = Permutation(str_32bits, P_Table)
    return FeistelResult
##############################################################################################





#####Feistel 函数#########################################################################################
"""
    function: Feistel function to create bit-stR_ing to permute with R_i -- a 32-bit stR_ing
    input: R_i_1--the (i-1)th back 32 bits string, K_i--the son secret key
    return: Feistel result (string type)
"""
def Feistel(R_i_1, K_i):
    if PRINT_FLAG == True: 
        print("> 正在执行feistel轮函数")
    E_ExpandResult = E_Expand(R_i_1)
    xorResult = XOROperation(E_ExpandResult, K_i)
    str_32_bits = []
    for i in range(8):
        str_6_bits = xorResult[i * 6: i * 6 + 6]
        str_32_bits += S_Box_Transformation(str_6_bits, i + 1)
    return "".join(P_Permutation(str_32_bits))
##############################################################################################





#########加密过程的的交叉迭代过程#####################################################################################
"""
    function: make cross iteration on L0, R0 for 16 times
    input: L0--the front 32 bits of 64-bits plain text , R0--the back 32 bits of plain text
    return: R16--the back iterated 32-bits result, L16--the front iterated 32-bits result 
"""
def CrossIterationInEncryption(L_0, R_0, SecretKey):
    if PRINT_FLAG == True: 
        print("> 正在进行加密过程的交叉迭代")
    R = ""
    L = ""
    tmp_R = R_0
    tmp_L = L_0
    sonKeyList = createSonKey(SecretKey)
    for i in range(1,17):
        L = tmp_R
        R = XOROperation(tmp_L,Feistel(tmp_R,sonKeyList[i - 1]))
        tmp_R = R
        tmp_L = L
    RL = R + L
    return RL 
##############################################################################################




#########解密过程的的交叉迭代过程#####################################################################################
"""
    function: make cross iteration on L0, R0 for 16 times
    input: L0--the front 32 bits of 64-bits cipher text , R0--the back 32 bits of cipher text
    return: R16--the back iterated 32-bits result, L16--the front iterated 32-bits result 
"""
def CrossIterationInDecryption(L_0, R_0, SecretKey):
    if PRINT_FLAG == True: 
        print("> 正在进行解密过程的交叉迭代")
    R = []
    L = []
    tmp_R = R_0
    tmp_L = L_0
    sonKeyList = createSonKey(SecretKey)
    for i in range(1,17):
        L = tmp_R
        R = XOROperation(tmp_L,Feistel(tmp_R,sonKeyList[16 - i]))
        tmp_R = R
        tmp_L = L
    RL = R + L
    return RL 
##############################################################################################




######P 逆置换########################################################################################
InversePermutationTable=[40,8,48,16,56,24,64,32,
                        39,7,47,15,55,23,63,31,
                        38,6,46,14,54,22,62,30,
                        37,5,45,13,53,21,61,29,
                        36,4,44,12,52,20,60,28,
                        35,3,43,11,51,19,59,27,
                        34,2,42,10,50,18,58,26,
                        33,1,41,9,49,17,57,25]

"""
    function: inverse permutation on the R16L16 bit-stR_ing
    input: R16--the back iterated 32-bits result, L16--the front iterated 32-bits result 
    return: ciphterText--64bits
"""
def InversePermutation(R_16_L_16):
    if PRINT_FLAG == True: 
        print("> 正在进行逆置换")
    cipherText = ""
    cipherText = Permutation(R_16_L_16, InversePermutationTable)
    return cipherText 
##############################################################################################





#####加密总函数#########################################################################################
def Encryption(plainText, secretKey):
    if PRINT_FLAG == True: 
        print("> 开始加密64位明文")
    M = list(plainText)
    L0, R0 = InitialPermutation(M)
    RL = CrossIterationInEncryption(L0, R0, secretKey)
    cipherText = "".join(InversePermutation(RL))
    return cipherText
##############################################################################################





######解密总函数###############################################################################
def Decryption(cipherText, secretKey):
    if PRINT_FLAG == True: 
        print("> 开始解密64位密文")
    M = list(cipherText)
    L0, R0 = InitialPermutation(M)
    RL = CrossIterationInDecryption(L0, R0, secretKey)
    decryptedText = "".join(InversePermutation(RL))
    return decryptedText
##############################################################################################



####随机生成64位key，8个字符#####################################################################
"""
    return: a 64-bits (8 bytes) string as a secret key
"""
def createSecrteKey():
    seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+=-"
    key = []
    for i in range(8):
        key.append(random.choice(seed))
    randomSecretKey = ''.join(key)
    return randomSecretKey
################################################################################################


##########8个字符的字符串转为ascii，然后转 0 1串####################################
def ToBitString(string_8_char):
    strList = []
    for i in range(8):
        strList.append(str(int2bin(ord(string_8_char[i]), 8)))
    return "".join(strList)
##################################################################################

########64位bits转为8个ascci字符###################################################
def ToAsciiChar(string_64_bits):
    strList = []
    bitList = list(string_64_bits)
    for i in range(8):
        if int("".join(bitList[i * 8: i * 8 + 8]), 2) < 8:
            continue
        # 八个bit一个处理单元，先转为10进制，然后转ascii，存入列表
        strList.append(chr(int("".join(bitList[i * 8: i * 8 + 8]), 2)))
    #print("ASCII:" + str(strList))
    return "".join(strList)
##################################################################################


if __name__ == "__main__":  
    """
    print("执行DES加密算法")
    M="0000000100100011010001010110011110001001101010111100110111101111"#测试的明文
    K="0001001100110100010101110111100110011011101111001101111111110001"#密钥
    print("明文是" + M)
    print("加密后:" + Encryption(M, K))
    print("解密后" + Decryption(Encryption(M,K), K))
    """
    print("【DES程序说明】")
    print("1. 明文文件默认为同目录下的plainText.txt，如需加密其他文件，请修改16到20行代码的文件变量。" )
    print("2. 密钥是随机生成的，保存在同目录的secretKey.txt文件中")
    print("3. 如果要显示加密和解密过程，可修改23行代码的打印变量，置为True")
    print("---------------------------------------------------------------------")
    continueSign = input("请按任意键执行加密和解密过程。。。")
    print("随机生成密钥中...")
    secretKey = createSecrteKey()
    with open(SECRET_KEY_FILE, 'w') as sf:
        sf.write(secretKey)
    print("密钥已写入文件" + SECRET_KEY_FILE + "!")
    secretKeyBitString = ToBitString(secretKey)
    print("得到密钥的 0 1字符串！")
    
    full_flag = True   # 分组为8的倍数的标志，为8则真
    PlainTextFile = open(PLAIN_TEXT_FILE, 'r')
    CipherTextFile = open(CIPHER_TEXT_FILE, 'w')
    DecryptTextFile = open(DECRYPT_TEXT_FILE, 'w')
    while True:
        text_8_bytes = PlainTextFile.read(8)
        if not text_8_bytes:
            print("读取明文文件到结尾啦")
            break
        if len(text_8_bytes) != 8:
            full_flag = False
          
        else:
            bitString = ToBitString(text_8_bytes)
            # 加密
            encryptStr = Encryption(bitString, secretKeyBitString)
            # 加密结果写入文件
            CipherTextFile.write(str(ToAsciiChar(encryptStr)))
            # 解密
            decryptStr = Decryption(encryptStr, secretKeyBitString)
            # 解密结果写入文件 
            DecryptTextFile.write(str(ToAsciiChar(decryptStr)))
          
        if full_flag == False:
            NumOfLostBytes = 8 - len(text_8_bytes)
            bitStringList = []
            for i in range(len(text_8_bytes)):
                bitStringList.append(int2bin(ord(text_8_bytes[i]), 8))
    
            full_8_bits = int2bin(NumOfLostBytes, 8)  # 填充的比特串
            # 填充的字节数 转为bitstring
            for i in range(NumOfLostBytes):
                bitStringList.append(full_8_bits)
            bitString = "".join(bitStringList)  #补全64位分组
             # 加密
            encryptStr = Encryption(bitString, secretKeyBitString)
            # 加密结果写入文件
            CipherTextFile.write(str(ToAsciiChar(encryptStr)))
            # 解密
            decryptStr = Decryption(encryptStr, secretKeyBitString)
            # 解密结果写入文件 
            DecryptTextFile.write(str(ToAsciiChar(decryptStr)))
            
    # 读取完整的8个字节分组字节，尾部填充8个字节，取值都为08
    if full_flag == True:
        zero_eight = "00001000"
        tmpList = []
        for i in range(8):
            tmpList.append(zero_eight)
        bitString = "".join(tmpList)
        # 加密
        encryptStr = Encryption(bitString, secretKeyBitString)
        # 加密结果写入文件
        CipherTextFile.write(str(ToAsciiChar(encryptStr)))
        # 解密
        decryptStr = Decryption(encryptStr, secretKeyBitString)
        # 解密结果写入文件 
        DecryptTextFile.write(str(ToAsciiChar(decryptStr)))  
    print("加密成功！")
    print("解密成功！")
    PlainTextFile.close()
    CipherTextFile.close()
    DecryptTextFile.close()
    with open(PLAIN_TEXT_FILE, 'r') as pf:
        data = pf.read()
        print("明文为：")
        print(data)
    with open(CIPHER_TEXT_FILE, 'r') as cf:
        data = cf.read()
        print("加密结果为：")
        print(data)
    with open(DECRYPT_TEXT_FILE, 'r') as df:
        data = df.read()
        print("解密结果为：")
        print(data)
