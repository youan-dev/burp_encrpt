package listener;

import burp.*;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.List;

/**
 * @author youan
 * @date 2022-11-05 23:42
 * @project symmetric_jx
 * @company 聚散安全
 * @description: 是一个愿意接纳小白，不断自我革旧留精的学习之地。
 */

public class MenuItemListener implements ActionListener {
    IBurpExtenderCallbacks callbacks;
    private IContextMenuInvocation invocation;

    PrintWriter stdout;
    PrintWriter stderr;

    JTextField jTextFieldType;
    JTextField jTextFieldKey;

    IExtensionHelpers helpers;


    public MenuItemListener(IContextMenuInvocation iContextMenuInvocation
            ,IBurpExtenderCallbacks callbacks
            , JTextField jTextFieldType
            ,JTextField jTextFieldKey){

        this.invocation  = iContextMenuInvocation;
        this.callbacks=callbacks;
        this.jTextFieldKey=jTextFieldKey;
        this.jTextFieldType=jTextFieldType;
    }

    /**
     * Invoked when an action occurs.
     *
     * @param event the event to be processed
     */
    @Override
    public void actionPerformed(ActionEvent event) {
        try {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            IHttpRequestResponse message = messages[0];

            //获取body，获取输入的key以及对称解密方式，然后解密后再塞回message
            helpers = callbacks.getHelpers();
            IRequestInfo iRequestInfo = helpers.analyzeRequest(message);
            List<IParameter> parameters = iRequestInfo.getParameters();

            stdout.println(parameters);
            stdout.println(jTextFieldType);
            stdout.println(jTextFieldKey);

            //发送到repeater中
            callbacks.sendToRepeater(message.getHttpService().getHost()
                    , message.getHttpService().getPort()
                    , true
                    ,message.getRequest()
                    ,"对称加密解密"
            );

            byte[] req = message.getRequest();
            String currentShortUrl = message.getHttpService().toString();
            stdout.println(currentShortUrl);

            /*******************从Proxy history中查找最新cookie***************************/
/*            IHttpRequestResponse[]  historyMessages = callbacks.getProxyHistory();
            int len =  historyMessages.length;
            for (int index=len; index >=0; index--) {
                IHttpRequestResponse item = historyMessages[index];

                String hisShortUrl = item.getHttpService().toString();
                if (currentShortUrl.equals(hisShortUrl)) {
                    IRequestInfo hisanalyzedRequest = this.callbacks.getHelpers().analyzeRequest(item);
                    List<String> headers = hisanalyzedRequest.getHeaders();

                    for (String header:headers) {
                        if (header.startsWith("Cookie:")) {
                            stdout.println("找到cookie---"+header);
                        }
                    }
                }
            }*/
        } catch (Exception e) {
            callbacks.printError(e.getMessage());
        }
    }
}