import Core.*;
import it.unisa.dia.gas.plaf.jpbc.util.io.Base64;

import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Interfaces extends JFrame{

    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private static final int AES_KEY_BIT = 256;
    private static final int IV_LENGTH_BYTE = 12;
    final static byte[] iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE);
    private static SecretKey secretKey;

    PublicKey publicK = new PublicKey();
    MasterPrivateKey mPrivateK = new MasterPrivateKey();
    PrivateKey privateK;
    Token token;
    CipherText cText;

    private JPanel mainPanel;
    private JPanel cardPanels;
    private JPanel flowLayout;
    private JButton keyGenerationCenterButton;
    private JButton dataOwnerButton;
    private JButton dataRequesterButton;
    private JPanel keyGenPanel;
    private JPanel dataOwnerPanel;
    private JPanel dataRequesterPanel;
    private JTextField attriSetsField;
    private JButton keyGenButton;
    private JLabel keyGenTooltip;
    private JButton exportKeyButton;
    private JButton encryptButton;
    private JTextField fromFile;
    private JLabel encryptionTooltip;
    private JTextField accessPolicy;
    private JButton addIntoSearchIndexButton;
    private JTextField ipfsLink;
    private JTextField keywords;
    private JTextField decryptFile;
    private JButton decryptFileButton;
    private JLabel decryptionTooltip;
    private JTextField searchedOrg;
    private JButton searchFileButton;
    private JLabel searchTooltip;
    private JTextField encryptPassword;
    private JTextField passcode;
    private JTextField decryptPassword;
    private JTextField inputAttributes;
    private JButton secretKeyGenerate;
    private JLabel secretKeyGenTooltip;
    private JTextField textField1;
    private JTextField textField2;
    private JTextField textField3;
    private JTextField searchedLoc;
    private JTextField searchedMon;
    private JTextField searchedYrs;
    private JButton smartContract;
    private JPanel smartContractPanel;
    private JTextField orgField;
    private JTextField locField;
    private JTextField monField;
    private JTextField yrsField;
    private JButton updateArraysButton;
    private JLabel smartContractTooltips;
    private JLabel uploadTooltips;
    private JTextField tokField;

    private String[] attrSets;

    public Interfaces() {

        boolean result = false;

        setTitle("SWE1904870 FYP Demo");
        setSize(1080, 720);
        setContentPane(mainPanel);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setVisible(true);

        keyGenerationCenterButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cardPanels.removeAll();
                cardPanels.add(keyGenPanel);
                cardPanels.repaint();
                cardPanels.revalidate();
            }
        });
        dataOwnerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cardPanels.removeAll();
                cardPanels.add(dataOwnerPanel);
                cardPanels.repaint();
                cardPanels.revalidate();
            }
        });
        dataRequesterButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cardPanels.removeAll();
                cardPanels.add(dataRequesterPanel);
                cardPanels.repaint();
                cardPanels.revalidate();
            }
        });
        smartContract.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cardPanels.removeAll();
                cardPanels.add(smartContractPanel);
                cardPanels.repaint();
                cardPanels.revalidate();
            }
        });
        keyGenButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String input = attriSetsField.getText();
                attrSets = input.split(",");

                //Debug
                for(String i: attrSets)
                    System.out.println(i);
                //DataProvider,DataAnalytics,Dep1,Dep2,Dep3,SeniorExecutive,JuniorExecutive

                ABSE.setup(attrSets, publicK, mPrivateK);
                keyGenTooltip.setText("Key has been generated.");
            }
        });
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                long startTime = System.currentTimeMillis();
                String selectedFile = fromFile.getText();
                String fileName = selectedFile;
                fileName = fileName.replace(".csv",".encrypted.csv");
                System.out.println(fileName);
                String password = encryptPassword.getText();
                try {
                    AESEncryption.encryptFile(selectedFile, fileName, password);
                    encryptionTooltip.setText("Encryption Done!");
                    System.out.println("Done!");
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                long stopTime = System.currentTimeMillis();
                long elapsedTime = stopTime - startTime;
                System.out.println(elapsedTime);
            }
        });
        decryptFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                long startTime = System.currentTimeMillis();
                decryptionTooltip.setText(" ");
                String selectedFile = decryptFile.getText();
                String password = decryptPassword.getText();
                byte[] decryptedText = new byte[0];
                try {
                    decryptedText = AESEncryption.decryptFile(selectedFile, password);
                } catch (Exception ex) {
                    ex.printStackTrace();
                    decryptionTooltip.setText("Decryption error! Please check the password.");
                }
                String pText = new String(decryptedText, UTF_8);
                String fileName = selectedFile;
                fileName = fileName.replace("encrypted", "decrypted");
                try {
                    FileWriter myWriter = new FileWriter(fileName);
                    myWriter.write(pText);
                    myWriter.close();
                    decryptionTooltip.setText("Decryption Done");
                } catch (IOException ex) {
                    ex.printStackTrace();
                    decryptionTooltip.setText("Decryption error! File path does not exist.");
                }
                long stopTime = System.currentTimeMillis();
                long elapsedTime = stopTime - startTime;
                System.out.println(elapsedTime);
            }
        });//Resources/readme.txt

        addIntoSearchIndexButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                boolean flag = true;
                String filePath = ipfsLink.getText();
                String temp = accessPolicy.getText();
                String[] accPolicy = temp.split(",");
                List<String> checkList = Arrays.asList(attrSets);
                for(int i = 0; i < accPolicy.length; i++)
                    if(!checkList.contains(accPolicy[i]))
                    {
                        System.out.println(accPolicy[i]);
                        uploadTooltips.setText("Error! Please check access policy!");
                        flag = false;
                    }
                    //DataProvider,DataAnalytics,Dep1,Dep2,Dep3,SeniorExecutive,JuniorExecutive
                if(flag)
                {
                    Index index = new Index("passphrase", filePath);
                    cText = ABSE.enc(attrSets, publicK, accPolicy, index);
                    String w0 = Base64.encodeBytes(cText.w0.toBytes());;
                    String w = Base64.encodeBytes(cText.w.toBytes());;
                    String uG = Base64.encodeBytes(cText.u_gate.toBytes());;
                    String tok = w0 + ";" + w + ";" + uG;
                    System.out.println(tok);
                    uploadTooltips.setText("Encryption Done! Added into search index.");
                }
            }
        });
        secretKeyGenerate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String[] userAttrs = inputAttributes.getText().split(",");
                privateK = ABSE.keygen(attrSets,publicK, mPrivateK, userAttrs);
                secretKeyGenTooltip.setText("Private key generated!");
            }
        });
        updateArraysButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String input1, input2, input3, input4, input5;
                input1 = orgField.getText();
                input2 = locField.getText();
                input3 = monField.getText();
                input4 = yrsField.getText();
                input5 = tokField.getText();
                Searching.indexLoad(input1,input2,input3,input4,input5);
                smartContractTooltips.setText("Index is updated");
            }
        });
        secretKeyGenerate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String[] userAttrs = inputAttributes.getText().split(",");
                privateK = ABSE.keygen(attrSets,publicK, mPrivateK, userAttrs);
            }
        });
        searchFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                long startTime = System.currentTimeMillis();
                String input1, input2, input3, input4;
                input1 = searchedOrg.getText();
                input2 = searchedLoc.getText();
                input3 = searchedMon.getText();
                input4 = searchedYrs.getText();
                if(input1.isEmpty())
                    input1 = "NULL";
                if(input2.isEmpty())
                    input2 = "NULL";
                if(input3.isEmpty())
                    input3 = "NULL";
                if(input4.isEmpty())
                    input4 = "NULL";
                System.out.println(input1);
                token = ABSE.tokenGen(privateK, publicK, "passphrase");
                Integer[] desiredPos = Searching.searchIndex(input1, input2, input3, input4);
                List<Integer> checkPos = Arrays.asList(desiredPos);
                if(checkPos.contains(-1))
                {
                    searchTooltip.setText("No File Found");
                }else
                {
                    try {
                        desiredPos = Searching.tokenCompare(publicK, token, desiredPos);
                        if(desiredPos.length != 0)
                        {
                                FileWriter writer = new FileWriter("Resources\\results.txt");
                                for(int i: desiredPos)
                                {
                                    writer.write(i + System.lineSeparator());
                                }
                                writer.close();
                                searchTooltip.setText("File Found");
                        }else
                            searchTooltip.setText("No File is Found!");
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
                long stopTime = System.currentTimeMillis();
                long elapsedTime = stopTime - startTime;
                System.out.println(elapsedTime);
            }
        });
    }

    public static void main(String[] args) {
        Interfaces myFrame = new Interfaces();
    }

    //Check to see whether the access policy attributes are valid
    public static boolean contains(final String[] array, final String v) {
        boolean isContain = false;
        for(String i : array){
            if(i.equals(v)){
                isContain = true;
                break;
            }
        }
        return isContain;
    }
}
