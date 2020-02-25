package org.crsh.command;

public class ShellSafety {
    private boolean safeShell = true;
    private boolean standAlone = false;
    private boolean internal = false;
    private boolean sshMode = false;
    private boolean allowExitInSafeMode = false;
    private boolean allowManCommand = false;
    private boolean isDefault = true;

    public ShellSafety() {
    }

    public ShellSafety(String safetyMode) {
        safeShell = safetyMode.contains("SAFESAFE");
        standAlone = safetyMode.contains("STANDALONE");
        internal = safetyMode.contains("INTERNAL");
        sshMode = safetyMode.contains("SSH");
        allowExitInSafeMode = safetyMode.contains("EXIT");
        allowManCommand = safetyMode.contains("MAN");
        isDefault = safetyMode.contains("DEFAULT");
    }

    public String toSafeString() {
        String ret = "";
        if (safeShell) { ret += "|SAFESAFE"; }
        if (standAlone) { ret += "|STANDALONE"; }
        if (internal) { ret += "|INTERNAL"; }
        if (sshMode) { ret += "|SSH"; }
        if (allowExitInSafeMode) { ret += "|EXIT"; }
        if (allowManCommand) { ret += "|MAN"; }
        if (isDefault) { ret += "|DEFAULT"; }
        return ret;
    }

    public String toString() {
        return toSafeString();
    }

    public boolean isDefault() {
        return isDefault;
    }

    public boolean isSafeShell() {
        return safeShell;
    }

    public boolean isStandAlone() {
        return standAlone;
    }

    public boolean isInternal() {
        return internal;
    }

    public boolean isSshMode() {
        return sshMode;
    }

    public boolean isAllowExitInSafeMode() {
        return allowExitInSafeMode;
    }

    public boolean isAllowManCommand() { return allowManCommand; }

    public void setDefault(boolean isDefault) {
        this.isDefault = isDefault;
    }

    public void setSafeShell(boolean safeShell) {
        this.safeShell = safeShell;
        this.isDefault = false;
    }

    public void setStandAlone(boolean standAlone) {
        this.standAlone = standAlone;
        this.isDefault = false;
    }

    public void setInternal(boolean internal) {
        this.internal = internal;
        this.isDefault = false;
    }

    public void setSSH(boolean sshMode) {
        this.sshMode = sshMode;
        this.isDefault = false;
    }

    public void setAllowExitInSafeMode(boolean exit) {
        this.allowExitInSafeMode = exit;
        this.isDefault = false;
    }

    public void setAllowManCommand(boolean allowMan) {
        this.allowManCommand = allowMan;
        this.isDefault = false;
    }

    public boolean permitExit() {
        return !isSafeShell() || !isInternal() || isSshMode() || isAllowExitInSafeMode();
    }
};
