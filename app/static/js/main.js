/**
 * NSAT Dashboard & Assessment Interactive Script
 */

document.addEventListener("DOMContentLoaded", function () {
  // Initialize all Bootstrap tooltips if any
  const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
  tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
  });

  // Handle Preset selection in New Assessment Wizard
  const presetRadios = document.querySelectorAll('input[name="port_preset"]');
  const customPortsInput = document.getElementById("portsCustomInput");
  const customPortsContainer = document.getElementById("customPortsContainer");

  if (presetRadios.length > 0 && customPortsInput) {
    presetRadios.forEach(function (radio) {
      radio.addEventListener("change", function () {
        if (this.value === "custom") {
          if (customPortsContainer) customPortsContainer.style.display = "block";
          customPortsInput.focus();
        } else {
          if (customPortsContainer) customPortsContainer.style.display = "none";
        }
      });
    });
  }

  // Live polling for in-progress assessments
  const liveStatusElem = document.getElementById("liveAssessmentMonitor");
  if (liveStatusElem) {
    const assessmentId = liveStatusElem.getAttribute("data-assessment-id");
    const statusEndpoint = liveStatusElem.getAttribute("data-status-url");

    if (assessmentId && statusEndpoint) {
      const pollInterval = setInterval(function () {
        fetch(statusEndpoint)
          .then(function (response) {
            return response.json();
          })
          .then(function (data) {
            if (data.status === "COMPLETED" || data.status === "FAILED" || data.status === "CANCELLED") {
              clearInterval(pollInterval);
              // Reload page once finished to display full results tables
              window.location.reload();
            } else {
              // Update live counters
              const portsBadge = document.getElementById("liveOpenPortsBadge");
              if (portsBadge) portsBadge.textContent = data.open_ports_count;

              const eventsBadge = document.getElementById("liveEventsCount");
              if (eventsBadge) eventsBadge.textContent = data.events_count;

              const durationElem = document.getElementById("liveDuration");
              if (durationElem && data.duration_seconds) {
                durationElem.textContent = data.duration_seconds + "s";
              }
            }
          })
          .catch(function (err) {
            console.error("Status polling error:", err);
          });
      }, 2500);
    }
  }
});
