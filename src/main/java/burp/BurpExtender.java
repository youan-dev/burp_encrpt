package burp;

import listener.MenuItemListener;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * @author youan
 * @date 2022-10-19 22:32
 * @project symmetric_encryption burp源码打包，直接右侧maven -> package 就行. 不需要打包插件.如果是springboot 工具就需要
 * @company 聚散安全
 * @description: 是一个愿意接纳小白，不断自我革旧留精的学习之地。
 *
 */

public class BurpExtender implements IBurpExtender,IHttpListener ,IContextMenuFactory ,ITab{

    IBurpExtenderCallbacks callbacks2;
    PrintWriter stdout;
    PrintWriter stderr;

    private JPanel jPanel1;
    private JButton jButton1;
    private JLabel jLabel1;

    JTextField jTextFieldType;
    JTextField jTextFieldKey;



    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks2=callbacks;
        // 设置插件的名称
        callbacks.setExtensionName("SE");

        // 获取burp提供的标准输出流和错误输出流
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // 打印到标准输出流
        stdout.println("Hello output");

        // 写一个报警信息到burp的报警面板
        callbacks.issueAlert("Hello alerts");

        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);
        //callbacks.addSuiteTab(this);

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                //创建一个 JPanel
                jPanel1 = new JPanel();

                // 将按钮添加到面板中
//                jButton1 = new JButton("点我");
//                jPanel1.add(jButton1);

                // 将文本标签添加到面板
                JLabel jLabelType = new JLabel("加密方式：");
                jTextFieldType = new JTextField(10);
                jPanel1.add(jLabelType);
                jPanel1.add(jTextFieldType);

                JLabel jLabelKey = new JLabel("秘钥：");
                jTextFieldKey = new JTextField(20);
                jPanel1.add(jLabelKey);
                jPanel1.add(jTextFieldKey);

                //自定义的 UI 组件
                callbacks.customizeUiComponent(jPanel1);
                //将自定义的标签页添加到Burp UI 中
                callbacks.addSuiteTab(BurpExtender.this);

            }
        });
    }

    /**
     * httpListener 方法重写
     * @param toolFlag
     * @param messageIsRequest
     * @param messageInfo
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        stdout.println(
                (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
                        messageInfo.getHttpService() +
                        " [" + callbacks2.getToolName(toolFlag) + "]");

        stderr.println("messageIsRequest:"+messageIsRequest);

        //获取请求头信息
//        IRequestInfo iRequestInfo = callbacks2.getHelpers().analyzeRequest(messageInfo);
//        List<String> headers = iRequestInfo.getHeaders();

        //这个捕捉repeater 是指在repeater中点击send按钮时触发的。也就是把明文转加密时用。
        if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER){
            // 打印到标准输出流
            stdout.println("Hello repeater!!!");
        }

    }

    /**
     * ContextMenuFactory 用于为自定义上下文菜单项注册工厂(注册右键菜单时需要)
     * @param iContextMenuInvocation
     * @return
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>();
        //子菜单
        JMenuItem menuItem;
        menuItem = new JMenuItem("解密");
        //父级菜单
        JMenu jMenu = new JMenu("send to jx_repeater");
        jMenu.add(menuItem);
        listMenuItems.add(jMenu);

        //对菜单进行监听
        menuItem.addActionListener(new MenuItemListener(iContextMenuInvocation,this.callbacks2,jTextFieldType,jTextFieldKey));
        return listMenuItems;
    }

    @Override
    public String getTabCaption() {
        return "面板";
    }

    @Override
    public Component getUiComponent() {
        return jPanel1;
    }
}
