namespace SystemForge;

/// <summary>
/// A real Windows dialog (outside the web dashboard) for the few actions that must never happen just because a page
/// asked: restarting the PC and deleting quarantined files for good.
/// </summary>
public static class NativeConfirm
{
    public static Form? Owner { get; set; }

    public static bool Ask(string title, string message)
    {
        var owner = Owner;
        if (owner is null || owner.IsDisposed) return false;
        bool Show() => MessageBox.Show(owner, message, title, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        try { return owner.InvokeRequired ? (bool)owner.Invoke(Show) : Show(); }
        catch { return false; }
    }
}
