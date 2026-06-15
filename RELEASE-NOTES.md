# NCM Monitor Release Notes

```text
NCM MONITOR RELEASE NOTES
=========================

CURRENT RELEASE
---------------

Version:
  v5.0.3 Golden

Release Name:
  Graph History Stabilization Release

Release Package:
  ncm-monitor-v5.0.3-golden.tar.gz

Recommended Next Version:
  v5.1.0 - Cell Tower Mapping

Purpose:
  Stabilize graph history behavior after v5.0.2 and prepare a clean golden
  package for fresh installs.


v5.0.3 GOLDEN
-------------

Summary:
  v5.0.3 stabilizes the router detail history graphs, especially the 90-day
  signal and usage history views.

Primary fixes:
  - Confirmed app.py compiles successfully.
  - Stabilized 90-day signal history rendering.
  - Stabilized 90-day usage history rendering.
  - Improved usage graph behavior when NCM cloud traffic is enabled.
  - Preserved SIM/WAN-only behavior when NCM cloud traffic is disabled.
  - Added support for daily_ncm_usage data in the router detail usage graph.
  - Confirmed currentUsageNcmRows is populated from daily_ncm_usage.
  - Improved renderUsageChart behavior for NCM router-stream usage history.
  - Improved graph start behavior when NCM router-stream data exists earlier
    than SIM/WAN usage rows.
  - Added or retained historyStartLine support for graph context markers.
  - Added/validated 5g_service_mode_change event handling.
  - Added UI labeling for 5g_service_mode_change.
  - Separated 5G service mode changes from normal cell tower/service type
    mobility display where appropriate.
  - Filtered 5G service mode changes from the cellular mobility card event
    list where needed.
  - Preserved router detail page behavior after graph changes.

Known notes:
  - Cell tower mapping is intentionally deferred to v5.1.0.
  - If graph behavior is revisited later, inspect:
      renderSignalChart
      renderUsageChart
      historyStartLinePlugin
      buildDayLabels
      daily_ncm_usage
      showNcmTrafficToggle


v5.0.2
------

Summary:
  v5.0.2 focused on router detail graph behavior, cellular event correlation,
  and 5G service mode visibility.

Fixes / enhancements:
  - Improved router detail graph rendering.
  - Added 5g_service_mode_change event support.
  - Added display mapping for 5G service mode change events.
  - Updated service type change handling to include 5G mode events.
  - Improved handling of cellular events around graph overlays.
  - Continued refinement of signal and usage graph history.
  - Continued work in app.py under the v5.0.2 working folder.


v5.0.1
------

Summary:
  v5.0.1 focused on pool behavior, device registration, and cleanup after
  the initial v5.0.0 monitoring model changes.

Fixes / enhancements:
  - Improved pool creation behavior.
  - Improved router assignment to pools.
  - Continued dashboard/profile isolation cleanup.
  - Improved device registration behavior.
  - Reduced cases where a router could be added but not fully populated.
  - Improved readiness for stock/fresh installs.
  - Continued removing account-specific assumptions from the stock build.


v5.0.0
------

Summary:
  v5.0.0 introduced the major v5 monitoring model and continued the transition
  from account-specific tooling to a reusable stock application.

Fixes / enhancements:
  - Refined background polling model.
  - Improved local caching strategy for monitored router data.
  - Continued multi-dashboard/profile support.
  - Improved per-dashboard isolation.
  - Preserved router detail views.
  - Preserved usage investigation workflow.
  - Preserved signal history workflow.
  - Preserved alert/failover/router log workflows.
  - Prepared the app for cleaner stock install behavior.


v4.1.2 GOLDEN
-------------

Summary:
  v4.1.2 was a stable stock package milestone.

Fixes / enhancements:
  - Verified clean golden tarball packaging.
  - Verified no runtime/sensitive files were included in the tarball.
  - Improved first-run setup stability.
  - Improved installer behavior on a fresh environment.
  - Improved per-dashboard odometer counts.
  - Improved usage XLSX export formatting.
  - Improved profile fallback behavior.
  - Improved router detail graph stability.
  - Verified app could be installed from a clean package with user-provided
    credentials.
  - Removed runtime data, generated secrets, databases, logs, backups, and
    local QA artifacts from release packaging.


v4.1.0 GOLDEN
-------------

Summary:
  v4.1.0 fixed several stock-build issues found during fresh install testing.

Fixes / enhancements:
  - Fixed pool/profile isolation issues.
  - Fixed add-router behavior in pool management.
  - Fixed odometer visibility/counting issues.
  - Fixed router logs page behavior.
  - Improved usage investigation UI.
  - Improved per-dashboard deep dive behavior.
  - Removed account-specific store power page from the stock build.
  - Improved neutral stock branding.


v4.0.0
------

Summary:
  v4.0.0 was an early stock build milestone.

Fixes / enhancements:
  - Introduced the stock install concept.
  - Added setup flow foundation.
  - Added dashboard/profile management foundation.
  - Continued migration away from account-specific assumptions.
  - Identified several issues later resolved in v4.1.x:
      pool isolation problems
      add-router failures
      deep-dive redirect issues
      usage chart overflow
      missing router detail data in some scenarios


v3.0.0 GOLDEN
-------------

Summary:
  v3.0.0 was an initial golden-package concept for turning the monitoring tool
  into a reusable local application.

Fixes / enhancements:
  - Created initial golden packaging approach.
  - Began separating runtime data from application code.
  - Established early release hygiene patterns.
  - Prepared the path toward stock installer behavior.
