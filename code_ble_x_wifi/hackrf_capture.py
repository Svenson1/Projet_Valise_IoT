import threading
import queue
import numpy as np
import hackrf
import time


class HackRfCapture:

    def __init__(self):
        # Configuration
        self.start_frequency = 2.4e9
        self.sdr_baseband = 20e6
        self.N = 2048
        self.iterations = 5

        self.last_chunks = []
        self.power = None
        self.samples = None

        self.peak_values = []
        self.peak_times = []

        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self._reader_thread = None

        # SDR
        self.hrf = hackrf.HackRF()
        self.hrf.center_freq = self.start_frequency
        self.hrf.sample_rate = 20e6

        # Fréquences correspondant aux bins FFT
        self.freqs = np.fft.fftshift(
            np.fft.fftfreq(
                self.N * self.iterations,
                1 / self.hrf.sample_rate / self.iterations
            )
        ) + (
            self.start_frequency
            + self.sdr_baseband * self.iterations / 2
        )

        self.DC_CORRECTION = 0

    def build_snapshot(self):
        if self.power is None:
            return

        return {
            "values_x": self.freqs.tolist(),
            "values_y": self.power.tolist(),
            "values_max": self.peak_values,
        }

    def start_capture(self):
        if self._reader_thread is not None:
            return

        self._capture_running = True

        self._reader_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True
        )

        self._reader_thread.start()


    def _capture_loop(self):
        while self._capture_running:
            self.update()


    def stop_capture(self):
        self._capture_running = False

        if self._reader_thread is not None:
            self._reader_thread.join(timeout=2)
            self._reader_thread = None

    def read_worker(self):
        try:
            if self.stop_event.is_set():
                return

            samples = self.hrf.read_samples(self.N)
            self.q.put(samples)

        except Exception as e:
            print("SDR error:", e)
            time.sleep(0.2)
            self.q.put(None)

    def swipe_frequency(self, frequency):
        self.hrf.center_freq = frequency

        self.stop_event.clear()

        thread = threading.Thread(target=self.read_worker)
        thread.daemon = True
        thread.start()

        thread.join(timeout=0.2)

        if self.q.empty() or thread.is_alive():
            return None, None

        samples = self.q.get()

        if samples is None or len(samples) == 0:
            return None, None

        # Correction DC
        self.DC_CORRECTION = (
            0.75 * self.DC_CORRECTION
            + 0.25 * np.mean(samples)
        )

        samples = samples - self.DC_CORRECTION

        # FFT
        spec = np.fft.fftshift(np.fft.fft(samples))

        # Puissance en dB
        power = 20 * np.log10(np.abs(spec) + 1e-12)

        return power, samples

    def build_spectrum(self):

        power_chunks = []
        samples_chunks = []

        center_frequency = (
            self.start_frequency
            + self.sdr_baseband / 2
        )

        while center_frequency < (
            self.start_frequency
            + self.sdr_baseband * self.iterations
        ):

            power, samples = self.swipe_frequency(
                center_frequency
            )

            if power is None:

                if len(self.last_chunks) == self.iterations:
                    power_chunks.append(
                        self.last_chunks[len(power_chunks)]
                    )
                else:
                    power_chunks.append(
                        np.zeros(self.N)
                    )

                samples_chunks.append({
                    "center_frequency": center_frequency,
                    "samples": np.zeros(self.N)
                })

            else:

                power_chunks.append(power)

                samples_chunks.append({
                    "center_frequency": center_frequency,
                    "samples": samples
                })

            center_frequency += self.sdr_baseband

        self.last_chunks = power_chunks

        return (
            np.concatenate(power_chunks),
            samples_chunks
        )

    def update(self):

        # start = time.perf_counter()

        self.power, self.samples = self.build_spectrum()

        self.comparePeakValues()

        # elapsed = (time.perf_counter() - start) * 1000

        # print(f"New frame in {elapsed:.2f} ms")

    def comparePeakValues(self):
        now = time.monotonic()

        if len(self.peak_values) != len(self.power):
            self.peak_values = [None] * len(self.power)
            self.peak_times = [0] * len(self.power)

        for i, power in enumerate(self.power):

            if power is None:
                continue

            if (
                self.peak_values[i] is None
                or now - self.peak_times[i] > 15
                or power > self.peak_values[i]
            ):
                self.peak_values[i] = power
                self.peak_times[i] = now
