# Re-opens the GhidraMAT findings panel inside Ghidra.
# The panel must have been created by running Analysis > GhidraMAT > Analyze
# at least once in the current Ghidra session.

# @author HalfTimeOfLife
# @category GhidraMAT
# @menupath Analysis.GhidraMAT.Show Findings
# @runtime PyGhidra

from javax.swing import JFrame, JOptionPane

from core.panel import PANEL_TITLE

for frame in JFrame.getFrames():
    if frame.getTitle() == PANEL_TITLE and frame.isDisplayable():
        frame.setVisible(True)
        frame.toFront()
        break
else:
    JOptionPane.showMessageDialog(
        None,
        "No findings panel found.\nRun Analysis → GhidraMAT → Analyze first.",
        "GhidraMAT",
        JOptionPane.INFORMATION_MESSAGE,
    )
