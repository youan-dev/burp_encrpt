package listener;

import burp.*;
import utils.AESUtil;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.AbstractList;
import java.util.ArrayList;
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
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.helpers = callbacks.getHelpers();
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

            //如果在url中的参数的值是 key=json格式的字符串 这种形式的时候，getParameters应该是无法获取到最底层的键值对的。
            IRequestInfo iRequestInfo = helpers.analyzeRequest(message);
            //获取header
            List<String> headers = iRequestInfo.getHeaders();

            List<IParameter> parameters = iRequestInfo.getParameters();


            stdout.println(jTextFieldType.getText());
            stdout.println(jTextFieldKey.getText());


            byte[] newRequest=message.getRequest(); //设置一个数组，用于存放每次更新参数后的 message.getRequest()
            if("AES".equals(jTextFieldType.getText())){
                for(IParameter iParameter:parameters ){
                    stdout.println("iParameter.getType():"+iParameter.getType());
                    stdout.println("iParameter.getValue():"+iParameter.getValue());
                    if(iParameter.getType()==6){ //6代表取body的参数
                        stdout.println("iParameter.getName():"+iParameter.getName());
                        stdout.println("iParameter.getValue():"+iParameter.getValue());
                        //解密iParameter
                        String aesValue = AESUtil.encrypt(iParameter.getValue(), jTextFieldKey.getText());
                        aesValue = URLEncoder.encode(aesValue);
                        //aesValue = "111111111111111111111111111111111";
                        //构造新的参数
                        //当body是json格式的时候，helpers.analyzeRequest(messageInfo).getParameters()这个方法也可以正常获取到键值对；但是PARAM_JSON等格式不能通过updateParameter方法来更新。
                        //如果在url中的参数的值是 key=json格式的字符串 这种形式的时候，getParameters应该是无法获取到最底层的键值对的。
                        IParameter newParameter = helpers.buildParameter(iParameter.getName(), aesValue, IParameter.PARAM_BODY);
                        //如果修改了header或者数修改了body，不能通过updateParameter，使用这个方法。
                        //newRequest = helpers.updateParameter(newRequest, newParameter);
                        newRequest = this.helpers.removeParameter(newRequest, iParameter);
                        newRequest = this.helpers.addParameter(newRequest, newParameter);

                    }
                }
            }

            IRequestInfo reqInfo2 = helpers.analyzeRequest(newRequest);
            String tmpreq = new String(newRequest);
            String messageBody = new String(tmpreq.substring(reqInfo2.getBodyOffset())).trim();
            newRequest = this.helpers.buildHttpMessage(headers, messageBody.getBytes());

            message.setRequest(newRequest);
            //byte[] request = message.getRequest();

            //发送到repeater中
            callbacks.sendToRepeater(message.getHttpService().getHost()
                    , message.getHttpService().getPort()
                    , true
                    ,message.getRequest()
                    ,"对称加密解密"
            );

            String currentShortUrl = message.getHttpService().toString();
            stdout.println(currentShortUrl);


        } catch (Exception e) {
            callbacks.printError(e.getMessage());
        }
    }

    /**
     * 更新json类型的参数
     * @param _request
     * @param headers
     * @param _params
     * @param _do_enc
     * @return byte[] 数组
     */
//    public byte[] update_req_params_json(byte[] _request, List<String> headers, String[] _params, Boolean _do_enc){
//        for(int i=0; i< _params.length; i++){
//            IParameter _p = this.helpers.getRequestParameter(_request, _params[i]);
//            if (_p == null || _p.getName().toString().length() == 0){ continue; }
//
//            String _str = "";
///*            if(_do_enc) {
//                _str = this.do_encrypt(_p.getValue().toString().trim());
//            }
//            else {
//                _str = AESUtil.decrypt(_p.getValue().toString().trim());
//            }*/
//
//            try {
//                _str = AESUtil.decrypt(_p.getValue().toString().trim(),"AES");
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//
//
//            //if(this._is_ovrr_req_body){
//            if(true){
//                if (!headers.contains(this._Header)) { headers.add(this._Header); }
//                _request = this.helpers.buildHttpMessage(headers, _str.getBytes());
//                return _request;
//            }
//
///*            if(this._is_ovrr_res_body){
//                if (!headers.contains(this._Header)) { headers.add(this._Header); }
//                _request = this.helpers.buildHttpMessage(headers, _str.getBytes());
//                return _request;
//            }*/
//
//
//            IRequestInfo reqInfo = helpers.analyzeRequest(_request);
//            String tmpreq = new String(_request);
//            String messageBody = new String(tmpreq.substring(reqInfo.getBodyOffset())).trim();
//
//            int _fi = messageBody.indexOf(_params[i]);
//            if(_fi < 0) { continue; }
//
//            _fi = _fi + _params[i].length() + 3;
//            int _si = messageBody.indexOf("\"", _fi);
////            print_output("update_req_params_json", _str);
////            print_output("update_req_params_json", messageBody.substring(0, _fi));
////            print_output("update_req_params_json", messageBody.substring(_si, messageBody.length()));
//            if (!headers.contains(this._Header)) { headers.add(this._Header); }
//            messageBody = messageBody.substring(0, _fi) + _str + messageBody.substring(_si, messageBody.length());
//            _request = this.helpers.buildHttpMessage(headers, messageBody.getBytes());
//
//        }
//        return _request;
//    }


}
