SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
COLUMNS = ["Severity", "Category", "Name", "Type", "MITRE"]
PANEL_TITLE = "GhidraMAT Findings"
ALL = "ALL"


class FindingsFilter:
    """Python filtering layer over a flat list of findings.

    Args:
        findings (list[Finding]): All findings from the analysis.
    """

    def __init__(self, findings):
        self._findings = list(findings)
        self._severity = ALL
        self._category = ALL
        self._type = ALL
        self._mitre = ALL

    def set_severity(self, severity):
        """Set the active severity filter.

        Args:
            severity (str): A severity level ("CRITICAL", "HIGH", "MEDIUM",
                "LOW") or ALL to disable severity filtering.
        """
        self._severity = severity

    def set_category(self, category):
        """Set the active category filter.

        Args:
            category (str): A category name (e.g. "anti_vm") or ALL to
                disable category filtering.
        """
        self._category = category

    def set_type(self, type_of_technique):
        """Set the active type of technique filter.

        Args:
            type_of_technique (str): A type of technique name (e.g. "imports") or ALL to
                disable type of technique filtering.
        """
        self._type = type_of_technique

    def set_mitre(self, mitre):
        """Set the active mitre filter.

        Args:
            mitre (str): A mitre name (e.g. "T1622") or ALL to
                disable mitre filtering.
        """
        self._mitre = mitre

    def apply(self):
        """Return the findings that match the current filter state.

        Returns:
            list[Finding]: Filtered subset, preserving original order.
        """
        return [
            f
            for f in self._findings
            if (self._severity == ALL or f.severity == self._severity)
            and (self._category == ALL or f.category == self._category)
            and (self._type == ALL or f.type == self._type)
            and (self._mitre == ALL or f.mitre == self._mitre)
        ]

    def severities(self):
        """Return the unique severity values present in the findings.

        Returns:
            list[str]: [ALL] followed by severities sorted by logical order
                (CRITICAL first, LOW last).
        """
        seen = sorted(
            {f.severity for f in self._findings},
            key=lambda s: SEVERITY_ORDER.get(s, 99),
        )
        return [ALL] + seen

    def categories(self):
        """Return the unique category values present in the findings.

        Returns:
            list[str]: [ALL] followed by category names sorted alphabetically.
        """
        return [ALL] + sorted({f.category for f in self._findings})

    def types_of_technique(self):
        """Return the unique type of technique values present in the findings.

        Returns:
            list[str]: [ALL] followed by type of technique names sorted alphabetically.
        """
        return [ALL] + sorted({f.type for f in self._findings})

    def mitres(self):
        """Return the unique mitre values present in the findings.

        Returns:
            list[str]: [ALL] followed by mitre names sorted alphabetically.
        """
        return [ALL] + sorted({f.mitre for f in self._findings})


def show_results_panel(findings, go_to_service):
    """Build the GhidraMAT results panel and show it as a JFrame.

    Args:
        findings (list[Finding]): All findings from the analysis.
        go_to_service: Ghidra GoToService for address navigation, or None.

    Returns:
        JFrame: The visible findings panel.
    """
    from java.awt import BorderLayout, Dimension
    from java.awt.event import ItemListener, MouseListener
    from java.lang import Object as JObject
    from java.util import Comparator as JComparator, Vector
    from javax.swing import (
        BorderFactory,
        Box,
        BoxLayout,
        JComboBox,
        JFrame,
        JLabel,
        JPanel,
        JScrollPane,
        JTable,
    )
    import jpype
    from javax.swing.table import DefaultTableModel, TableRowSorter

    # ----------------------------------------------------------------
    # Close any panel left over from a previous Analyze run.
    # ----------------------------------------------------------------
    for frame in JFrame.getFrames():
        if frame.getTitle() == PANEL_TITLE:
            frame.dispose()
            break

    # ----------------------------------------------------------------
    # Filter state + DefaultTableModel (no subclassing needed).
    # ----------------------------------------------------------------
    ffilter = FindingsFilter(findings)
    _state = {"rows": ffilter.apply()}

    col_vector = Vector()
    for c in COLUMNS:
        col_vector.add(c)
    model = DefaultTableModel(col_vector, 0)

    def _populate():
        model.setRowCount(0)
        _state["rows"] = ffilter.apply()
        for f in _state["rows"]:
            row = Vector()
            for v in [f.severity, f.category, f.name, f.type, f.mitre or ""]:
                row.add(v)
            model.addRow(row)

    _populate()

    # ----------------------------------------------------------------
    # JTable with column sorting -- severity sorted by logical order.
    # ----------------------------------------------------------------
    table = JTable(model)
    table.setDefaultEditor(JObject, None)
    table.setFillsViewportHeight(True)
    table.setRowHeight(20)
    table.getTableHeader().setReorderingAllowed(False)

    @jpype.JImplements(JComparator)
    class _SeverityComparator:
        @jpype.JOverride
        def compare(self, a, b):
            return SEVERITY_ORDER.get(str(a), 99) - SEVERITY_ORDER.get(str(b), 99)

        @jpype.JOverride
        def equals(self, other):
            return self is other

    sorter = TableRowSorter(model)
    sorter.setComparator(0, _SeverityComparator())
    table.setRowSorter(sorter)

    # ----------------------------------------------------------------
    # Double-click navigation.
    # ----------------------------------------------------------------
    @jpype.JImplements(MouseListener)
    class _DoubleClickListener:
        @jpype.JOverride
        def mouseClicked(self, event):
            if event.getClickCount() != 2:
                return
            view_row = table.rowAtPoint(event.getPoint())
            if view_row < 0:
                return
            model_row = table.convertRowIndexToModel(view_row)
            f = _state["rows"][model_row]
            addr = f.primary_address()
            if addr is not None and go_to_service is not None:
                go_to_service.goTo(addr)

        @jpype.JOverride
        def mousePressed(self, event):
            pass

        @jpype.JOverride
        def mouseReleased(self, event):
            pass

        @jpype.JOverride
        def mouseEntered(self, event):
            pass

        @jpype.JOverride
        def mouseExited(self, event):
            pass

    table.addMouseListener(_DoubleClickListener())

    # ----------------------------------------------------------------
    # Filter bar -- two rows, four combo-boxes.
    # ----------------------------------------------------------------
    sev_combo = JComboBox(ffilter.severities())
    cat_combo = JComboBox(ffilter.categories())
    type_combo = JComboBox(ffilter.types_of_technique())
    mitre_combo = JComboBox(ffilter.mitres())

    @jpype.JImplements(ItemListener)
    class _FilterListener:
        @jpype.JOverride
        def itemStateChanged(self, event):
            ffilter.set_severity(str(sev_combo.getSelectedItem()))
            ffilter.set_category(str(cat_combo.getSelectedItem()))
            ffilter.set_type(str(type_combo.getSelectedItem()))
            ffilter.set_mitre(str(mitre_combo.getSelectedItem()))
            _populate()

    listener = _FilterListener()
    sev_combo.addItemListener(listener)
    cat_combo.addItemListener(listener)
    type_combo.addItemListener(listener)
    mitre_combo.addItemListener(listener)

    def _make_row(*widgets):
        row = JPanel()
        row.setLayout(BoxLayout(row, BoxLayout.X_AXIS))
        for w in widgets:
            row.add(w)
        row.add(Box.createHorizontalGlue())
        return row

    gap = Box.createRigidArea(Dimension(12, 0))
    gap2 = Box.createRigidArea(Dimension(12, 0))
    row1 = _make_row(
        JLabel("Severity: "), sev_combo, gap, JLabel("Category: "), cat_combo
    )
    row2 = _make_row(JLabel("Type: "), type_combo, gap2, JLabel("MITRE: "), mitre_combo)

    filter_bar = JPanel()
    filter_bar.setLayout(BoxLayout(filter_bar, BoxLayout.Y_AXIS))
    filter_bar.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))
    filter_bar.add(row1)
    filter_bar.add(Box.createRigidArea(Dimension(0, 3)))
    filter_bar.add(row2)

    # ----------------------------------------------------------------
    # Assemble the JFrame.
    # ----------------------------------------------------------------
    content = JPanel(BorderLayout())
    content.add(filter_bar, BorderLayout.NORTH)
    content.add(JScrollPane(table), BorderLayout.CENTER)

    frame = JFrame(PANEL_TITLE)
    frame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE)
    frame.setContentPane(content)
    frame.setSize(1100, 620)
    frame.setLocationRelativeTo(None)
    frame.setVisible(True)

    return frame
