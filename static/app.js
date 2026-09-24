document.addEventListener('DOMContentLoaded', function () {
  const navToggle = document.querySelector('.nav-toggle');
  const navLinks = document.querySelector('.navlinks');

  if (navToggle && navLinks) {
    navToggle.addEventListener('click', function () {
      navLinks.classList.toggle('open');
    });
  }

  const bookingForm = document.getElementById('bookingForm');
  const reviewBtn = document.getElementById('reviewBookingBtn');
  const confirmBtn = document.getElementById('confirmBookingBtn');
  const modal = document.getElementById('bookingModal');
  const availabilityData = document.getElementById('bookingAvailabilityData');
  const bookedDatesData = document.getElementById('bookingBookedDates');
  const rateData = document.getElementById('bookingRateData');
  const dateInput = document.getElementById('session_date');
  const timeSelectionHint = document.getElementById('timeSelectionHint');
  const bookingTimeSummary = document.getElementById('bookingTimeSummary');
  const startInput = document.getElementById('start_time');
  const endInput = document.getElementById('end_time');

  if (dateInput && availabilityData) {
    const availabilityByDay = JSON.parse(availabilityData.dataset.availability || '{}');
    const bookingsByDate = JSON.parse(bookedDatesData ? bookedDatesData.dataset.bookings || '{}' : '{}');
    const validWeekdays = new Set(Object.keys(availabilityByDay));
    const hourlyRate = Number(rateData ? rateData.dataset.rate : 0) || 0;
    const today = new Date();
    const minDateStr = new Date(today.getFullYear(), today.getMonth(), today.getDate()).toISOString().split('T')[0];
    dateInput.min = minDateStr;

    function weekdayNameForDate(value) {
      if (!value) return '';
      const date = new Date(`${value}T12:00:00`);
      return date.toLocaleDateString('en-US', { weekday: 'long' });
    }

    function timeToMinutes(value) {
      if (!value) return null;
      const [hours, minutes] = value.split(':').map(Number);
      return hours * 60 + minutes;
    }

    function timeRangesOverlap(startA, endA, startB, endB) {
      const startAMin = timeToMinutes(startA);
      const endAMin = timeToMinutes(endA);
      const startBMin = timeToMinutes(startB);
      const endBMin = timeToMinutes(endB);
      if (startAMin === null || endAMin === null || startBMin === null || endBMin === null) {
        return false;
      }
      return startAMin < endBMin && endAMin > startBMin;
    }

    function formatDisplayTime(value) {
      if (!value) return '';
      const [hours, minutes] = value.split(':').map(Number);
      const suffix = hours >= 12 ? 'PM' : 'AM';
      const hour12 = hours % 12 === 0 ? 12 : hours % 12;
      return `${hour12}:${String(minutes).padStart(2, '0')} ${suffix}`;
    }

    function getSelectedDateRanges() {
      const selectedDate = dateInput.value;
      if (!selectedDate) return [];
      const weekday = weekdayNameForDate(selectedDate);
      return availabilityByDay[weekday] || [];
    }

    function updateTimeRangeConstraints() {
      const ranges = getSelectedDateRanges();
      if (!ranges.length) {
        startInput.min = '';
        startInput.max = '';
        endInput.min = '';
        endInput.max = '';
        return;
      }

      const startTimes = ranges.map(function (range) { return range.start; });
      const endTimes = ranges.map(function (range) { return range.end; });
      startInput.min = startTimes.reduce(function (min, current) {
        return current < min ? current : min;
      }, startTimes[0]);
      startInput.max = endTimes.reduce(function (max, current) {
        return current > max ? current : max;
      }, endTimes[0]);
      endInput.min = startInput.min;
      endInput.max = startInput.max;
    }

    function updateBookingSummary() {
      const start = startInput.value;
      const end = endInput.value;
      if (!start || !end) {
        bookingTimeSummary.textContent = 'Session duration and fee will appear here after you choose valid times.';
        return;
      }

      const startMinutes = timeToMinutes(start);
      const endMinutes = timeToMinutes(end);
      if (startMinutes === null || endMinutes === null || endMinutes <= startMinutes) {
        bookingTimeSummary.textContent = 'End time must be later than the start time.';
        return;
      }

      const durationMinutes = endMinutes - startMinutes;
      const durationHours = durationMinutes / 60;
      const expectedFee = hourlyRate > 0 ? hourlyRate * durationHours : 0;
      const durationLabel = `${Math.floor(durationMinutes / 60)}h ${durationMinutes % 60}m`;
      bookingTimeSummary.textContent = `Session duration: ${durationLabel}. Estimated fee: ₱${expectedFee.toFixed(2)}.`;
    }

    function validateSelectedTimes() {
      const selectedDate = dateInput.value;
      if (!selectedDate) {
        return;
      }

      const weekday = weekdayNameForDate(selectedDate);
      const ranges = availabilityByDay[weekday] || [];
      const start = startInput.value;
      const end = endInput.value;

      if (!start || !end) {
        return;
      }

      const startMinutes = timeToMinutes(start);
      const endMinutes = timeToMinutes(end);
      if (startMinutes === null || endMinutes === null || endMinutes <= startMinutes) {
        startInput.setCustomValidity('End time must be later than the start time.');
        endInput.setCustomValidity('End time must be later than the start time.');
        return;
      }

      const inAvailability = ranges.some(function (range) {
        const rangeStart = timeToMinutes(range.start);
        const rangeEnd = timeToMinutes(range.end);
        return rangeStart !== null && rangeEnd !== null && startMinutes >= rangeStart && endMinutes <= rangeEnd;
      });

      if (!inAvailability) {
        startInput.setCustomValidity('Times must fall inside the tutor’s availability window.');
        endInput.setCustomValidity('Times must fall inside the tutor’s availability window.');
        return;
      }

      const existingBookings = bookingsByDate[selectedDate] || [];
      const hasConflict = existingBookings.some(function (booking) {
        return timeRangesOverlap(start, end, booking.start, booking.end);
      });
      if (hasConflict) {
        startInput.setCustomValidity('This time overlaps an existing booking.');
        endInput.setCustomValidity('This time overlaps an existing booking.');
        return;
      }

      startInput.setCustomValidity('');
      endInput.setCustomValidity('');
    }

    function refreshBookingControls() {
      const selectedDate = dateInput.value;
      if (!selectedDate) {
        timeSelectionHint.textContent = 'Choose a date to set exact start and end times.';
        bookingTimeSummary.textContent = 'Session duration and fee will appear here after you choose valid times.';
        startInput.value = '';
        endInput.value = '';
        return;
      }

      const weekday = weekdayNameForDate(selectedDate);
      if (!validWeekdays.has(weekday)) {
        dateInput.setCustomValidity('This date does not match the tutor\'s availability.');
        dateInput.reportValidity();
        dateInput.value = '';
        timeSelectionHint.textContent = 'This weekday is not in the tutor’s availability schedule.';
        bookingTimeSummary.textContent = 'Session duration and fee will appear here after you choose valid times.';
        startInput.value = '';
        endInput.value = '';
        return;
      }

      dateInput.setCustomValidity('');
      updateTimeRangeConstraints();
      timeSelectionHint.textContent = `Available on ${weekday}. Select any exact start and end time that falls inside the tutor’s availability window.`;
      validateSelectedTimes();
      updateBookingSummary();
    }

    dateInput.addEventListener('change', refreshBookingControls);
    startInput.addEventListener('change', function () {
      validateSelectedTimes();
      updateBookingSummary();
    });
    endInput.addEventListener('change', function () {
      validateSelectedTimes();
      updateBookingSummary();
    });

    if (dateInput.value) {
      refreshBookingControls();
    }
  }

  if (bookingForm && reviewBtn && modal) {
    reviewBtn.addEventListener('click', function () {
      const subjectSelect = document.getElementById('subject_id');
      const dateInput = document.getElementById('session_date');
      const startInput = document.getElementById('start_time');
      const endInput = document.getElementById('end_time');

      if (!dateInput.value || !startInput.value || !endInput.value) {
        timeSelectionHint.textContent = 'Please choose a valid date and a session time from the available options.';
        return;
      }

      document.getElementById('modalSubject').textContent = subjectSelect.options[subjectSelect.selectedIndex]?.text || 'Not selected';
      document.getElementById('modalDate').textContent = dateInput.value || 'Not selected';
      document.getElementById('modalTime').textContent = startInput.value && endInput.value
        ? `${startInput.value} - ${endInput.value}`
        : 'Not selected';

      modal.classList.remove('hidden');
      modal.setAttribute('aria-hidden', 'false');
    });

    document.querySelectorAll('[data-close-modal]').forEach(function (button) {
      button.addEventListener('click', function () {
        modal.classList.add('hidden');
        modal.setAttribute('aria-hidden', 'true');
      });
    });

    if (confirmBtn) {
      confirmBtn.addEventListener('click', function () {
        bookingForm.submit();
      });
    }
  }
});
