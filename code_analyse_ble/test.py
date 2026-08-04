from nrf_capture import BleCapture
import time

c = BleCapture()
c.start_capture()
time.sleep(10)
c.stop_capture()

while not c.queue.empty():
    print(c.queue.get())