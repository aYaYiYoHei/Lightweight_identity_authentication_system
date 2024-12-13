package socket;

import Decoder.BASE64Decoder;
import Decoder.BASE64Encoder;
import PW.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static PW.SIGN.*;

public class Client extends JFrame implements Runnable, ActionListener{

    private JTextArea chatArea;
    private JTextField iptextField,porttextField,messageField;
    private JButton connectionButton,sendButton;
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private Thread thread;
    private JComboBox namecomboBox;


    public Client(){
        createUserInterface();
        setTitle("客服端");
        setSize(550,500);
        setResizable(false);
        setLocationRelativeTo(null);
        setVisible(true);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
    public void createUserInterface(){
        setLayout(new FlowLayout());
        add(new JLabel("主机"));
        iptextField=new JTextField(10);
        iptextField.setText("127.0.0.1");
        add(iptextField);
        add(new JLabel("端口"));
        porttextField=new JTextField(10);
        porttextField.setText("9999");
        add(porttextField);
        add(new JLabel("使用人"));
        namecomboBox=new JComboBox();
        namecomboBox.addItem("User1");
        namecomboBox.addItem("User2");
        add(namecomboBox);
        connectionButton=new JButton("连接");
        add(connectionButton);
        chatArea=new JTextArea(20,40);
        chatArea.setEnabled(false);
        add(new JScrollPane(chatArea));
        messageField=new JTextField(20);
        add(messageField);
        sendButton=new JButton("发送");
        add(sendButton);
        this.getRootPane().setDefaultButton(sendButton);
        connectionButton.addActionListener(this);
        sendButton.addActionListener(this);
        socket=new Socket();
        thread=new Thread(this);

    }
    public void connect(){
        try{
            if(!socket.isConnected()){
                InetAddress address=InetAddress.getByName(iptextField.getText());
                InetSocketAddress socketAddress=new InetSocketAddress(address, Integer.parseInt(porttextField.getText()));
                socket.connect(socketAddress);
                in=new DataInputStream(socket.getInputStream());
                out=new DataOutputStream(socket.getOutputStream());
                sendButton.setEnabled(true);
                if(!thread.isAlive()){
                    thread=new Thread(this);
                }
                thread.start();
            }
        }catch(Exception e){
            System.out.println(e);
            socket=new Socket();
        }
    }
    public void send(){
        String msg=messageField.getText().trim();
        if(msg.isEmpty()){
            JOptionPane.showMessageDialog(this, "请输入发送信息:");
            return;
        }
        chatArea.append(namecomboBox.getSelectedItem()+":"+msg+"\n");
        try{
            msg=namecomboBox.getSelectedItem()+":"+msg+"\n";
            byte[] re = DES.encrypt(msg.getBytes(),DES.pw);
            BASE64Encoder encoder = new BASE64Encoder();
            String result = encoder.encode(re);
            StringBuffer HS = MD5.HashMD5(msg);
            String prikey = null;
            try {
                prikey = SIGN.getKeyFromFile("D:/649110974/FileRecv/MobileFile/src (1)/src_new/PW/client_rsa_private_key.pem");
            } catch (Exception e) {
                e.printStackTrace();
            }
            SIGN.SecretKey secretKey = new SIGN.SecretKey(null,prikey);
            String SHS = encryptData(HS.toString(), secretKey.getPrivateKey());
            result = result + " " + SHS;
            out.writeUTF(result);
            messageField.setText("");
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if(e.getSource()==sendButton){
            send();
        }else if(e.getSource()==connectionButton){
            connect();
        }
    }

    @Override
    public void run() {
        if(Thread.currentThread()==thread){
            String msg = null;
            String str = null;
            String deStr = null;
            while(true){
                try{
                    msg=in.readUTF();
                    String[] mid = msg.split(" ");
                    BASE64Decoder decoder = new BASE64Decoder();
                    byte[] re = decoder.decodeBuffer(mid[0]);
                    byte[] result = DES.decrypt(re,DES.pw);
                    str=new String(result);
                    StringBuffer hash = MD5.HashMD5(str);
                    String Hash = hash.toString();
                    String pubkey = null;
                    try {
                        pubkey = SIGN.getKeyFromFile("D:/649110974/FileRecv/MobileFile/src (1)/src/PW/server_rsa_public_key.pem");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    SIGN.SecretKey secretKey = new SIGN.SecretKey(pubkey,null);
                    deStr = decryptData(mid[1], secretKey.getPublicKey());
                    if(Hash.compareTo(deStr)==0){
                        chatArea.append(str);
                    } else {
                        chatArea.append("由服务器发来的信息遭到篡改！！\n");
                    }
                }catch(IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e){
                    e.printStackTrace();
                    socket=new Socket();
                    break;
                }
            }
        }
    }
    public static void main(String[] args){
        EventQueue.invokeLater(new Runnable(){
            public void run(){
                try{
                    Client frame=new Client();
                    frame.setVisible(true);
                }catch(Exception e){
                    e.printStackTrace();
                }
            }
        });
    }
}