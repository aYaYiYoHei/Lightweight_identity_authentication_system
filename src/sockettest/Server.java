package sockettest;

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

public class Server extends JFrame implements Runnable,ActionListener{
    private JTextArea chatArea;
    private JTextField porttextField,messageField;
    private JButton startButton,sendButton;
    private ServerSocket serversocket;
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private Thread thread;


    public Server(){
        createUserInterface();
        setTitle("服务器");
        setSize(550,500);
        setResizable(false);
        setLocationRelativeTo(null);
        setVisible(true);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
    public void createUserInterface(){
        setLayout(new FlowLayout());
        add(new JLabel("端口"));
        porttextField=new JTextField(22);
        porttextField.setText("9999");
        add(porttextField);
        startButton=new JButton("启动");
        add(startButton);
        chatArea=new JTextArea(20,40);
        chatArea.setEnabled(false);
        add(new JScrollPane(chatArea));
        messageField=new JTextField(20);
        add(messageField);
        sendButton=new JButton("发送");
        add(sendButton);
        this.getRootPane().setDefaultButton(sendButton);
        startButton.addActionListener(this);
        sendButton.addActionListener(this);
        thread=new Thread(this);

    }
    public void connect(){
        try{
            chatArea.append("请稍等...\n");
            serversocket=new ServerSocket(Integer.parseInt(porttextField.getText()));
            socket=serversocket.accept();
            chatArea.append("连接成功...\n");
            in=new DataInputStream(socket.getInputStream());
            out=new DataOutputStream(socket.getOutputStream());
            if(!thread.isAlive()){
                thread=new Thread(this);
            }
            thread.start();
        }catch(Exception e){
            System.out.println(e);
            try{
                serversocket=new ServerSocket();
            }catch(IOException e1){
                e1.printStackTrace();
            }
        }
    }
    public void send(){
        String msg=messageField.getText().trim();
        if(msg.isEmpty()){
            JOptionPane.showMessageDialog(this, "请输入发送信息:");
            return;
        }
        chatArea.append("服务器:"+msg+"\n");
        try{
            msg="服务器:"+msg+"\n";
            byte[] re = DES.encrypt(msg.getBytes(),DES.pw);
            BASE64Encoder encoder = new BASE64Encoder();
            String result = encoder.encode(re);
            StringBuffer HS = MD5.HashMD5(msg);
            String prikey = null;
            try {
                prikey = SIGN.getKeyFromFile("D:/649110974/FileRecv/MobileFile/src (1)/src/PW/server_rsa_private_key.pem");
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
        }else if(e.getSource()==startButton){
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
                        pubkey = SIGN.getKeyFromFile("D:/649110974/FileRecv/MobileFile/src (1)/src/PW/client_rsa_public_key.pem");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    SIGN.SecretKey secretKey = new SIGN.SecretKey(pubkey,null);
                    deStr = decryptData(mid[1], secretKey.getPublicKey());
                    if(Hash.compareTo(deStr)==0){
                        chatArea.append(str);
                    } else {
                        chatArea.append("由客户端发来的信息遭到篡改！！\n");
                    }
                }catch(IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e){
                    e.printStackTrace();
                    try {
                        serversocket=new ServerSocket();
                    } catch (IOException ioException) {
                        ioException.printStackTrace();
                    }
                    break;
                }
            }
        }
    }
    public static void main(String[] args){
        EventQueue.invokeLater(new Runnable(){
            public void run(){
                try{
                    Server frame=new Server();
                    frame.setVisible(true);
                }catch(Exception e){
                    e.printStackTrace();
                }
            }
        });
    }
}