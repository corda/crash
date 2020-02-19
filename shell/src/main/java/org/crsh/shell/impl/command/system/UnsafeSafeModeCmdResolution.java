package org.crsh.shell.impl.command.system;

import org.crsh.cli.Usage;
import org.crsh.command.BaseCommand;
import org.crsh.command.InvocationContext;
import org.crsh.text.Color;
import org.crsh.text.Decoration;
import org.crsh.text.Style;
import org.crsh.text.ui.LabelElement;

import java.util.HashMap;

public class UnsafeSafeModeCmdResolution {
    public static abstract class UnSafeCommand extends BaseCommand {

        UnSafeCommand() {
        }

        public abstract String getCommandName();

        @Usage("Command is not available when shell is in Safe mode.")
        @org.crsh.cli.Command
        public void main(InvocationContext<Object> context) throws Exception {
            context.provide(new LabelElement("Unsafe system/script command [" + getCommandName()
                    + "] is not available with shell in safe mode.").style(Style.style(Decoration.bold, Color.red)));
        }
    }

    // Adds safe dummy handlers for unsafe commands in the safe mode
    static void addSafeHandlers(HashMap<String, Class<? extends BaseCommand>> safeCommandsHandlers, boolean exitAllowed, boolean manAllowed) {
        if (!exitAllowed) {
            safeCommandsHandlers.put("bye", Bye.class);
        }
        safeCommandsHandlers.put("dashboard", Dashboard.class);
        safeCommandsHandlers.put("egrep", EGrep.class);
        safeCommandsHandlers.put("env", Env.class);
        if (!exitAllowed) {
            safeCommandsHandlers.put("exit", Exit.class);
        }
        safeCommandsHandlers.put("filter", Filter.class);
        safeCommandsHandlers.put("java", CJava.class);
        safeCommandsHandlers.put("jdbc", Jdbc.class);
        safeCommandsHandlers.put("jndi", Jndi.class);
        safeCommandsHandlers.put("jpa", Jpa.class);
        safeCommandsHandlers.put("jul", Jul.class);
        safeCommandsHandlers.put("jvm", Jvm.class);
        safeCommandsHandlers.put("less", Less.class);
        if (!manAllowed) {
            addSafeHandlerForMan(safeCommandsHandlers);
        }
        safeCommandsHandlers.put("repl", CRepl.class);
        safeCommandsHandlers.put("shell", CShell.class);
        safeCommandsHandlers.put("sleep", Sleep.class);
        safeCommandsHandlers.put("sort", Sort.class);
        safeCommandsHandlers.put("system", CSystem.class);
        safeCommandsHandlers.put("thread", CThread.class);
    }

    static void addSafeHandlerForMan(HashMap<String, Class<? extends BaseCommand>> safeCommandsHandlers) {
        safeCommandsHandlers.put("man", CMan.class);
    }

    public static class Bye extends UnSafeCommand { public String getCommandName() { return "bye"; } }
    public static class Dashboard extends UnSafeCommand { public String getCommandName() { return "dashboard"; } }
    public static class EGrep extends UnSafeCommand { public String getCommandName() { return "egrep"; } }
    public static class Env extends UnSafeCommand { public String getCommandName() { return "env"; } }
    public static class Exit extends UnSafeCommand { public String getCommandName() { return "exit"; } }
    public static class Filter extends UnSafeCommand { public String getCommandName() { return "filter"; } }
    public static class CJava extends UnSafeCommand { public String getCommandName() { return "java"; } }
    public static class Jdbc extends UnSafeCommand { public String getCommandName() { return "jdbc"; } }
    public static class Jndi extends UnSafeCommand { public String getCommandName() { return "jndi"; } }
    public static class Jpa extends UnSafeCommand { public String getCommandName() { return "jpa"; } }
    public static class Jul extends UnSafeCommand { public String getCommandName() { return "jul"; } }
    public static class Jvm extends UnSafeCommand { public String getCommandName() { return "jvm"; } }
    public static class Less extends UnSafeCommand { public String getCommandName() { return "less"; } }
    public static class CMan extends UnSafeCommand { public String getCommandName() { return "man"; } }
    public static class CRepl extends UnSafeCommand { public String getCommandName() { return "repl"; } }
    public static class CShell extends UnSafeCommand { public String getCommandName() { return "shell"; } }
    public static class Sleep extends UnSafeCommand { public String getCommandName() { return "sleep"; } }
    public static class Sort extends UnSafeCommand { public String getCommandName() { return "sort"; } }
    public static class CSystem extends UnSafeCommand { public String getCommandName() { return "system"; } }
    public static class CThread extends UnSafeCommand { public String getCommandName() { return "thread"; } }
}
