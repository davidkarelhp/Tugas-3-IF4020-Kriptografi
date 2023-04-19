package com.fsck.k9.JARL;
import org.apache.commons.math3.util.Pair;

import java.util.*;
import java.nio.charset.Charset;

public class JARL {
    public static void SysoutLn(Object obj) {
        System.out.println(obj);
    }

    public static void Sysout(Object obj) {
        System.out.print(obj);
    }

    public static void main(String[] args) throws Exception {
        Charset charset = Charset.forName("UTF-8");

        String keyEncrypt = "MBCHc1RWuPJIDxn0";

        String inputString = "Kami bangsa Indonesia dengan ini menjatakan Kemerdekaan Indonesia.\n" +
            "Hal-hal jang mengenai pemindahan kekoeasaan d.l.l., diselenggarakan dengan tjara seksama dan dalam tempo jang sesingkat-singkatnja.\n" +
            "Djakarta, hari 17 boelan 8 tahoen 05\n" +
            "Atas nama bangsa Indonesia\n" +
            "Soekarno/Hatta.";

        String hexCipherText = encryptStringToHexString(inputString, keyEncrypt);

        SysoutLn("Hex Cipher Text = " + hexCipherText);

        String decryptedText = decryptHexStringToString(hexCipherText, keyEncrypt);
        SysoutLn("Decrypted Text = " + decryptedText);

    }

    public static boolean isValidKey(String key) {
        Charset charset = Charset.forName("UTF-8");
        byte[] keyBytes = key.getBytes(charset);

        return keyBytes.length == 16;

    }

    public static String encryptStringToHexString(String plaintext, String key) throws Exception {
        Charset charset = Charset.forName("UTF-8");

        byte[] keyBytes = key.getBytes(charset);

        byte[] plaintextBytes = plaintext.getBytes(charset);

        byte[] encryptedBytes = encrypt(plaintextBytes, keyBytes);

        return bytesToHex(encryptedBytes);
    }

    public static String decryptHexStringToString(String ciphertext, String key) throws Exception {
        Charset charset = Charset.forName("UTF-8");

        byte[] keyBytes = key.getBytes(charset);

        byte[] ciphertextBytes = hexToBytes(ciphertext);

        byte[] decryptedBytes = decrypt(ciphertextBytes, keyBytes);

        return new String(decryptedBytes, charset);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] hexToBytes(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                + Character.digit(hexString.charAt(i+1), 16));
        }
        return data;
    }

    public static byte[] encrypt(byte[] plaintext, byte[] key) throws Exception {
        if (key.length != 16) {
            System.out.printf("\nKey Length = %d bytes\n", key.length);
            throw new Exception("Key length has to be 128 bits (16 bytes)");
        }

        if (plaintext.length % 16 != 0) {
            plaintext = paddingBlocks(plaintext);
        }

        Integer[] keyInt = new Integer[key.length];

        for (int i = 0; i < key.length; i++) {
            keyInt[i] = convertByteToUnsignedInteger(key[i]);
        }

        long start = System.currentTimeMillis();
        List<Integer[]> blocks = splitBytesIntoBlocks(plaintext);

        Pair<Integer[], Integer[]> splitKey = split128BitTo64Bit(keyInt);
        Matrix keyMatrix = generateMatrixFrom64Bit(XOR(splitKey.getFirst(), splitKey.getSecond()));

        byte[] ciphertext = new byte[plaintext.length];
        int currentIndex = 0;

        for (Integer[] block : blocks) {
            block = XOR(block, keyInt);
            Pair<Integer[], Integer[]> lrPair = split128BitTo64Bit(block);
            Integer[] left = lrPair.getFirst();
            Integer[] right = lrPair.getSecond();

            for (int i = 0; i < 16; i++) {
                Matrix rightMatrix = generateMatrixFrom64Bit(right);
                Matrix roundKey = rightMatrix.multiply(keyMatrix).transpose();
                modulo16(roundKey);
                Integer[] tempRight = right;
                right = cipherFunctionEncrypt(left, roundKey);

                left = tempRight;
            }

            List<Integer> resultList = new ArrayList<Integer>(left.length + right.length);
            Collections.addAll(resultList, left);
            Collections.addAll(resultList, right);
            Integer[] blockBytes = resultList.toArray(new Integer[0]);
            blockBytes = XOR(blockBytes, keyInt);

            for (int i = 0; i < blockBytes.length; i++) {
                ciphertext[currentIndex] = (byte)(int) blockBytes[i];
                currentIndex++;
            }
        }

        long end = System.currentTimeMillis();
        System.out.printf("Encryption Elapsed Time = %d ms\n", end - start);

        return ciphertext;
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key) throws Exception {
        if (key.length != 16) {
            System.out.printf("\nKey Length = %d bytes\n", key.length);
            throw new Exception("Key length has to be 128 bit (16 bytes)");
        }
        if (ciphertext.length % 16 != 0) {
            System.out.printf("\nCiphertext Length = %d bytes\n", ciphertext.length);
            throw new Exception("Ciphertext length has to be multiple of 128 bit (16 bytes)");
        }

        long start = System.currentTimeMillis();
        List<Integer[]> blocks = splitBytesIntoBlocks(ciphertext);

        Integer[] keyInt = new Integer[key.length];

        for (int i = 0; i < key.length; i++) {
            keyInt[i] = convertByteToUnsignedInteger(key[i]);
        }

        Pair<Integer[], Integer[]> splitKey = split128BitTo64Bit(keyInt);
        Matrix keyMatrix = generateMatrixFrom64Bit(XOR(splitKey.getFirst(), splitKey.getSecond()));

        byte[] plaintext = new byte[ciphertext.length];
        int currentIndex = 0;
        int blockIndex = 0;
        int stopIndex = ciphertext.length - 1;

        for (Integer[] block : blocks) {
            block = XOR(block, keyInt);
            Pair<Integer[], Integer[]> lrPair = split128BitTo64Bit(block);
            Integer[] left = lrPair.getFirst();
            Integer[] right = lrPair.getSecond();

            for (int i = 0; i < 16; i++) {
                Matrix leftMatrix = generateMatrixFrom64Bit(left);
                Matrix roundKey = leftMatrix.multiply(keyMatrix).transpose();
                modulo16(roundKey);

                Integer[] tempLeft = left;
                left = cipherFunctionDecrypt(right, roundKey);
                right = tempLeft;
            }

            List<Integer> resultList = new ArrayList<Integer>(left.length + right.length);
            Collections.addAll(resultList, left);
            Collections.addAll(resultList, right);
            Integer[] blockBytes = resultList.toArray(new Integer[0]);
            blockBytes = XOR(blockBytes, keyInt);

            for (int i = 0; i < blockBytes.length; i++) {
                if (blockIndex == blocks.size() - 1 && blockBytes[i] == 0) {
                    stopIndex = currentIndex;
                    break;
                }

                plaintext[currentIndex] = (byte)(int) blockBytes[i];
                currentIndex++;
            }

            blockIndex++;
        }

        long end = System.currentTimeMillis();
        System.out.printf("Decryption Elapsed Time = %d ms\n", end - start);

        return Arrays.copyOfRange(plaintext, 0, stopIndex);
    }

    public static Integer[] cipherFunctionEncrypt(Integer[] bytes, Matrix roundKey) {
        Map<Integer, int[]> playfairMap = fillPlayFairMatrix(roundKey);
        List<Pair<Integer, Integer>> bigrams = split64BitTo4BitBigrams(bytes);
        Integer[] ret = new Integer[bigrams.size()];

        for (int i = 0; i < bigrams.size(); i++) {
            Pair<Integer, Integer> bigram = bigrams.get(i);
            Pair<Integer, Integer> result = playfairAlgorithmEncrypt(bigram, roundKey, playfairMap);
            ret[i] = ((result.getFirst() << 4) | result.getSecond());
        }

        Matrix shiftMatrix = generateMatrixFrom64Bit(ret);
        permutateEncrypt(shiftMatrix, roundKey);


        return generate64BitFromMatrix(shiftMatrix);
    }

    public static Integer[] cipherFunctionDecrypt(Integer[] bytes, Matrix roundKey) {
        Map<Integer, int[]> playfairMap = fillPlayFairMatrix(roundKey);

        Matrix shiftMatrix = generateMatrixFrom64Bit(bytes);

        permutateDecrypt(shiftMatrix, roundKey);
        bytes = generate64BitFromMatrix(shiftMatrix);

        List<Pair<Integer, Integer>> bigrams = split64BitTo4BitBigrams(bytes);

        Integer[] ret = new Integer[bigrams.size()];
//        playfairMap.forEach((key, val) -> {
//            Sysout(key + " = ");
//            SysoutLn(Arrays.toString(val));
//        });
//        SysoutLn(bigrams);

        for (int i = 0; i < bigrams.size(); i++) {
            Pair<Integer, Integer> bigram = bigrams.get(i);
            Pair<Integer, Integer> result = playfairAlgorithmDecrypt(bigram, roundKey, playfairMap);
            ret[i] = ((result.getFirst() << 4) | result.getSecond());
        }
//        SysoutLn(Arrays.toString(ret));

        return ret;
    }

    public static Pair<Integer, Integer> playfairAlgorithmEncrypt(Pair<Integer, Integer> bigram, Matrix matrix, Map<Integer, int[]> playfairMap) {
        int retFirst = 0;
        int retSecond = 0;

        int first = bigram.getFirst();
        int second = bigram.getSecond();

        if (playfairMap.get(first)[0] == playfairMap.get(second)[0]) {
            retFirst = matrix.getElement(playfairMap.get(first)[0], (playfairMap.get(first)[1] + 1) % 4);
            retSecond = matrix.getElement(playfairMap.get(second)[0], (playfairMap.get(second)[1] + 1) % 4);
        } else if (playfairMap.get(first)[1] == playfairMap.get(second)[1]) {
            retFirst = matrix.getElement((playfairMap.get(first)[0] + 1) % 4, playfairMap.get(first)[1]);
            retSecond = matrix.getElement((playfairMap.get(second)[0] + 1) % 4, playfairMap.get(second)[1]);
        } else {
            retFirst = matrix.getElement(playfairMap.get(first)[0], playfairMap.get(second)[1]);
            retSecond = matrix.getElement(playfairMap.get(second)[0], playfairMap.get(first)[1]);
        }

        return new Pair<Integer, Integer>(retFirst, retSecond);
    }

    public static Pair<Integer, Integer> playfairAlgorithmDecrypt(Pair<Integer, Integer> bigram, Matrix matrix, Map<Integer, int[]> playfairMap) {
        int retFirst = 0;
        int retSecond = 0;

        int first = bigram.getFirst();
        int second = bigram.getSecond();

        if (playfairMap.get(first)[0] == playfairMap.get(second)[0]) {
            retFirst = matrix.getElement(playfairMap.get(first)[0],Math.floorMod (playfairMap.get(first)[1] - 1, 4));
            retSecond = matrix.getElement(playfairMap.get(second)[0], Math.floorMod(playfairMap.get(second)[1] - 1, 4));
        } else if (playfairMap.get(first)[1] == playfairMap.get(second)[1]) {
            retFirst = matrix.getElement(Math.floorMod(playfairMap.get(first)[0] - 1, 4), playfairMap.get(first)[1]);
            retSecond = matrix.getElement(Math.floorMod(playfairMap.get(second)[0] - 1, 4), playfairMap.get(second)[1]);
        } else {
            retFirst = matrix.getElement(playfairMap.get(first)[0], playfairMap.get(second)[1]);
            retSecond = matrix.getElement(playfairMap.get(second)[0], playfairMap.get(first)[1]);
        }

        return new Pair<Integer, Integer>(retFirst, retSecond);
    }

    public static void shiftRowsLikeAES(Matrix matrix, boolean encrypt) {
        for (int i = 1; i < 4; i++) {
            if (encrypt) {
                matrix.setRow(i, new int[]{
                    matrix.getElement(i, (i) % 4),
                    matrix.getElement(i, (1 + i) % 4),
                    matrix.getElement(i, (2 + i) % 4),
                    matrix.getElement(i, (3 + i) % 4)});
            } else {
                matrix.setRow(i, (new int[]{
                    matrix.getElement(i, Math.floorMod(-i, 4)),
                    matrix.getElement(i, Math.floorMod(1 - i, 4)),
                    matrix.getElement(i, Math.floorMod(2 - i, 4)),
                    matrix.getElement(i, Math.floorMod(3 - i, 4))}));
            }
        }
    }

    public static void permutateEncrypt(Matrix matrix, Matrix roundKey) {
        int roundKeyNumber = 0;
        for (int i = 0; i < roundKey.rows(); i++) {
            for (int j = 0; j < roundKey.columns(); j++) {
                if (i % 2 == 0) {
                    if (j % 2 == 0) {
                        roundKeyNumber += roundKey.getElement(i, j);
                    } else {
                        roundKeyNumber -= roundKey.getElement(i, j);
                    }
                } else {
                    if (j % 2 == 0) {
                        roundKeyNumber -= roundKey.getElement(i, j);
                    } else {
                        roundKeyNumber += roundKey.getElement(i, j);
                    }
                }
            }
        }

        if (roundKeyNumber >= 0) {
            shiftRowsLikeAES(matrix, true);
            shiftDiagonalDown(matrix);
            clockwiseRotate(matrix);
        } else {
            shiftDiagonalUp(matrix);
            counterclockwiseRotate(matrix);
            shiftRowsLikeAES(matrix, true);
        }
    }

    public static void permutateDecrypt(Matrix matrix, Matrix roundKey) {
        int roundKeyNumber = 0;
        for (int i = 0; i < roundKey.rows(); i++) {
            for (int j = 0; j < roundKey.columns(); j++) {
                if (i % 2 == 0) {
                    if (j % 2 == 0) {
                        roundKeyNumber += roundKey.getElement(i, j);
                    } else {
                        roundKeyNumber -= roundKey.getElement(i, j);
                    }
                } else {
                    if (j % 2 == 0) {
                        roundKeyNumber -= roundKey.getElement(i, j);
                    } else {
                        roundKeyNumber += roundKey.getElement(i, j);
                    }
                }
            }
        }

        if (roundKeyNumber >= 0) {
            counterclockwiseRotate(matrix);
            shiftDiagonalUp(matrix);
            shiftRowsLikeAES(matrix, false);
        } else {
            shiftRowsLikeAES(matrix, false);
            clockwiseRotate(matrix);
            shiftDiagonalDown(matrix);
        }
    }

    public static void clockwiseRotate(Matrix matrix) {
        Matrix temp = new Matrix(new int[][]{
            {matrix.getElement(0, 0)}, {matrix.getElement(1, 0)}, {matrix.getElement(0, 1)}, {matrix.getElement(0, 3)},
            {matrix.getElement(2, 0)}, {matrix.getElement(1, 1)}, {matrix.getElement(1, 2)}, {matrix.getElement(0, 2)},
            {matrix.getElement(3, 1)}, {matrix.getElement(2, 1)}, {matrix.getElement(2, 2)}, {matrix.getElement(1, 3)},
            {matrix.getElement(3, 0)}, {matrix.getElement(3, 2)}, {matrix.getElement(2, 3)}, {matrix.getElement(3, 3)}
        });
        matrix = temp;
    }

    public static void counterclockwiseRotate(Matrix matrix) {
        Matrix temp = new Matrix(new int[][]{
            {matrix.getElement(0, 0)}, {matrix.getElement(0, 2)}, {matrix.getElement(1, 3)}, {matrix.getElement(0, 3)},
            {matrix.getElement(0, 1)}, {matrix.getElement(1, 1)}, {matrix.getElement(1, 2)}, {matrix.getElement(2, 3)},
            {matrix.getElement(1, 0)}, {matrix.getElement(2, 1)}, {matrix.getElement(2, 2)}, {matrix.getElement(3, 2)},
            {matrix.getElement(3, 0)}, {matrix.getElement(2, 0)}, {matrix.getElement(3, 1)}, {matrix.getElement(3, 3)}
        });
        matrix = temp;
    }

    public static void shiftDiagonalDown(Matrix matrix) {
        Matrix temp = new Matrix(new int[][]{
            {matrix.getElement(3, 3)}, {matrix.getElement(0, 1)}, {matrix.getElement(0, 2)}, {matrix.getElement(3, 0)},
            {matrix.getElement(1, 0)}, {matrix.getElement(0, 0)}, {matrix.getElement(0, 3)}, {matrix.getElement(1, 3)},
            {matrix.getElement(2, 0)}, {matrix.getElement(1, 2)}, {matrix.getElement(1, 1)}, {matrix.getElement(2, 3)},
            {matrix.getElement(2, 1)}, {matrix.getElement(3, 1)}, {matrix.getElement(3, 2)}, {matrix.getElement(2, 2)}
        });
        matrix = temp;
    }

    public static void shiftDiagonalUp(Matrix matrix) {
        Matrix temp = new Matrix(new int[][]{
            {matrix.getElement(1, 1)}, {matrix.getElement(0, 1)}, {matrix.getElement(0, 2)}, {matrix.getElement(1, 2)},
            {matrix.getElement(1, 0)}, {matrix.getElement(2, 2)}, {matrix.getElement(2, 1)}, {matrix.getElement(1, 3)},
            {matrix.getElement(2, 0)}, {matrix.getElement(3, 0)}, {matrix.getElement(3, 3)}, {matrix.getElement(2, 3)},
            {matrix.getElement(0, 3)}, {matrix.getElement(3, 1)}, {matrix.getElement(3, 2)}, {matrix.getElement(0, 0)}
        });
        matrix = temp;
    }

    public static Map<Integer, int[]> fillPlayFairMatrix(Matrix matrix) {
        Map<Integer, int[]> ret = new HashMap<>();
        Set<Integer> existInMatrix = new HashSet<>();
        Set<Integer> emptyIndex = new HashSet<>();

        for (int i = 0; i < matrix.rows(); i++) {
            for (int j = 0; j < matrix.columns(); j++) {
                int value = matrix.getElement(i, j);
                if (!existInMatrix.contains(value)) {
                    existInMatrix.add(value);
                    ret.put(value, new int[]{i, j});
                } else {
                    emptyIndex.add(i * 4 + j);
                }
            }
        }

        int numberFill = 0;
        for (int element : emptyIndex) {
            while (numberFill < 16) {
                if (!existInMatrix.contains(numberFill)) {
                    int i = element / 4;
                    int j = element - ((element / 4) * 4);
                    matrix.setElement(i, j, numberFill);
                    existInMatrix.add(numberFill);
                    ret.put(numberFill, new int[]{i, j});
                    break;
                }
                numberFill++;
            }
        }

        return ret;
    }

    public static Pair<Integer, Integer> split8BitTo4Bit(Integer b) {
        int first = b >> 4;
        int second = (b & 0x0F);
        return new Pair<>(first, second);
    }

    public static Pair<Integer[], Integer[]> split128BitTo64Bit(Integer[] bytes) {
        Integer[] first = new Integer[8];
        Integer[] second = new Integer[8];

        for (int i = 0; i < 8; i++) {
            first[i] = bytes[i];
            second[i] = bytes[i + 8];
        }

        return new Pair<>(first, second);
    }

    public static List<Pair<Integer, Integer>> split64BitTo4BitBigrams(Integer[] byteArr) {
        List<Pair<Integer, Integer>> ret = new ArrayList<>();
        for (Integer element : byteArr) {
            Pair<Integer, Integer> pair = JARL.split8BitTo4Bit(element);
            ret.add(pair);
        }
        return ret;
    }

    public static Matrix generateMatrixFrom64Bit(Integer[] bytes) {
        int[][] matrix = new int[4][4];
        for (int i = 0; i < 8; i++) {
            Pair<Integer, Integer> parts = split8BitTo4Bit(bytes[i]);
            matrix[i/2][i%2*2] = parts.getFirst();
            matrix[i/2][i%2*2+1] = parts.getSecond();
        }

        return new Matrix(matrix);
    }

    public static Integer[] generate64BitFromMatrix(Matrix matrix) {
        byte byteVal = 0;
        Integer[] ret = new Integer[8];
        int index = 0;

        for (int i = 0; i < matrix.rows(); i++) {
            for (int j = 0; j < matrix.columns(); j++) {
                if (j % 2 == 0) {
                    byteVal = (byte) (matrix.getElement(i, j) << 4);
                } else {
                    byteVal |= matrix.getElement(i, j);
                    ret[index++] = convertByteToUnsignedInteger(byteVal);
                }
            }
        }

        return ret;
    }

    public static List<Integer[]> splitBytesIntoBlocks(byte[] byteArray) {
        List<Integer[]> ret = new ArrayList<>();
        int byteLen = byteArray.length;
        int numOfBlocks = (int) Math.ceil(byteLen / 16.0);
        Integer[] intArray = new Integer[byteLen];
        for (int i = 0; i < byteLen; i++) {
            intArray[i] = convertByteToUnsignedInteger(byteArray[i]);
        }

        for (int i = 0; i < numOfBlocks; i++) {
            int startIndex = i * 16;
            int endIndex = Math.min((i * 16) + 16, byteLen);
            Integer[] block = new Integer[endIndex - startIndex];
            System.arraycopy(intArray, startIndex, block, 0, endIndex - startIndex);
            ret.add(block);
        }

        return ret;
    }

    public static Integer[] XOR(Integer[] bytes1, Integer[] bytes2) {
        Integer[] result = new Integer[bytes1.length];
        for (int i = 0; i < bytes1.length; i++) {
            result[i] = bytes1[i] ^ bytes2[i];
        }
        return result;
    }

    public static void modulo16(Matrix matrix) {
        // Apply modulo 16 operation to each element of the matrix
        for (int i = 0; i < matrix.rows(); i++) {
            for (int j = 0; j < matrix.columns(); j++) {
                int element = matrix.getElement(i, j);
                matrix.setElement(i, j, Math.floorMod(element, 16));
            }
        }
    }

    public static int convertByteToUnsignedInteger(byte b) {
        if (b < 0) {
            return  ((int) b) + 256;
        } else {
            return (int) b;
        }
    }

    public static byte[] paddingBlocks(byte[] bytes) {
        if (bytes.length % 16 != 0) {
            byte[] newBytes = new byte[bytes.length + (16 - (bytes.length % 16))];
            for (int i = 0; i < newBytes.length; i++) {
                if (i < bytes.length) {
                    newBytes[i] = bytes[i];
                } else {
                    newBytes[i] = 0;
                }
            }

            return newBytes;
        } else {
            return bytes;
        }
    }
}
