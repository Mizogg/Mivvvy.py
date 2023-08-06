import  platform, sys, os
import random
import secp256k1 as ice
from bloomfilter import BloomFilter
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.progressbar import ProgressBar
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.togglebutton import ToggleButton
from kivy.graphics import RoundedRectangle, Color
from kivy.metrics import sp  # Import sp for setting font size
from kivy.clock import Clock, mainthread
from kivy.properties import NumericProperty, StringProperty
from kivy.uix.image import Image
from kivy.core.window import Window
from kivy.lang import Builder
import time
import threading
from threading import Thread

mizogg = f'''

 Made by Mizogg Version 1.1  © mizogg.co.uk 2018 - 2023      {f"[>] Running with Python {sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}"}

'''

try:
    with open('btc.bf', "rb") as fp:
        addfind = BloomFilter.load(fp)
except FileNotFoundError:
    filename = 'btc.txt'
    with open(filename) as file:
        addfind = file.read().split()

class CustomProgressBar(ProgressBar):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.value_text = Label(font_size=sp(12), bold=True)
        self.add_widget(self.value_text)

    def on_size(self, instance, value):
        self.value_text.pos = (self.x + self.width / 2 - self.value_text.texture_size[0] / 2, self.y - sp(15))

    def on_value(self, instance, value):
        self.value_text.text = f"Progress: {value / self.max * 100:.2f}%"
        self.value_text.pos = (self.x + self.width / 2 - self.value_text.texture_size[0] / 2, self.y - sp(15))


class KeyGenerationThread(threading.Thread):
    def __init__(self, priv_start, priv_end, order, progress_bar, on_progress, on_result, stop_flag):
        super(KeyGenerationThread, self).__init__()
        self.priv_start = priv_start
        self.priv_end = priv_end
        self.order = order
        self.found_count = 0
        self.progress_bar = progress_bar
        self.on_progress = on_progress
        self.on_result = on_result
        self.stop_flag = stop_flag
        self.lock = threading.Lock()

    def process_address(self, btc_type, address, private_key):
        with self.lock:
            if self.stop_flag.is_set():
                return
            if address in addfind:
                if btc_type == 'comp':
                    wifc = ice.btc_pvk_to_wif(private_key)
                    found_data = f'\nFOUND!! \nPrivate Key: {hex(private_key)} \nCompressed Address: {address}\nCompressed WIF: {wifc} \n'
                elif btc_type == 'uncomp':
                    wifu = ice.btc_pvk_to_wif(HEX, False)
                    found_data = f'\nFOUND!! \nPrivate Key: {hex(private_key)} \nUncompressed Address: {address}\nUncompressed WIF: {wifu} \n'
                with open('found.txt', 'a') as result:
                    result.write(found_data)
                self.found_count += 1
                self.on_result(found_data)
    def stop(self):
        self.stop_flag.set()
        
    def generate_keys(self, priv_start, priv_end):
        keys_generated = 0
        total_keys_scanned = 0
        start_time = time.time()
        max_value = 10000
        group_size = 1000
        stop_size = 100
        try:
            if self.order == 'sequence':
                    private_key = priv_start
                    P = ice.scalar_multiplication(private_key)
                    current_pvk = private_key + 1
                    while current_pvk < priv_end:
                        if keys_generated % stop_size == 0 and self.stop_flag.is_set():
                            return
                        for i in range(priv_start, priv_end, group_size):
                            Pv = ice.point_sequential_increment(group_size, P)
                            for t in range(group_size):
                                compresses_btc = ice.pubkey_to_address(0, True, Pv[t * 65:t * 65 + 65])
                                uncompresses_btc = ice.pubkey_to_address(0, False, Pv[t * 65:t * 65 + 65])
                                self.process_address('comp', compresses_btc, current_pvk + t)
                                self.process_address('uncomp', uncompresses_btc, current_pvk + t)
                                with self.lock:
                                    if keys_generated % group_size == 0:
                                        keys_per_sec = keys_generated / (time.time() - start_time)
                                        self.on_progress(keys_generated, keys_per_sec, current_pvk + t, compresses_btc, uncompresses_btc)
                                        current_step = int((current_pvk + t - priv_start) * max_value / (priv_end - priv_start))
                                        self.progress_bar.value = current_step
                                    keys_generated += 1

                            P = Pv[-65:]
                            current_pvk += group_size
            elif self.order == 'random':
                while True:
                    if keys_generated % stop_size == 0 and self.stop_flag.is_set():
                        return
                    private_key = random.randrange(priv_start, priv_end)
                    P = ice.scalar_multiplication(private_key)
                    current_pvk = private_key + 1
                    for i in range(group_size):
                        Pv = ice.point_sequential_increment(group_size, P)
                        for t in range(group_size):
                            compresses_btc = ice.pubkey_to_address(0, True, Pv[t * 65:t * 65 + 65])
                            uncompresses_btc = ice.pubkey_to_address(0, False, Pv[t * 65:t * 65 + 65])
                            self.process_address('comp', compresses_btc, current_pvk + t)
                            self.process_address('uncomp', uncompresses_btc, current_pvk + t)
                            with self.lock:
                                if keys_generated % group_size == 0:
                                    keys_per_sec = keys_generated / (time.time() - start_time)
                                    self.on_progress(keys_generated, keys_per_sec, current_pvk + t, compresses_btc, uncompresses_btc)
                                    current_step = int((current_pvk + t - priv_start) * max_value / (priv_end - priv_start))
                                    self.progress_bar.value = current_step
                                keys_generated += 1
                        P = Pv[-65:]
                        current_pvk += group_size
        except KeyboardInterrupt:
            print("Program interrupted. Cleaning up...")
            return False
        return True

    def generate_keys_and_callback(self, dt):
        self.generate_keys(self.priv_start, self.priv_end)

    def run(self):
        self.generate_keys(self.priv_start, self.priv_end)
        if self.stop_flag.is_set():
            print("Thread stopped.")
        else:
            print("Thread completed.")

Builder.load_string('''
<RoundedToggleButton>:
    canvas.before:
        Color:
            rgba: (1, 0, 0, 1) if self.state == 'normal' else (0.7, 0.7, 1, 1)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [50, 25, 50, 25] if self.state == 'normal' else [0]
''')

class RoundedToggleButton(ToggleButton):
    pass
        
class WinnerDialog(Popup):
    def __init__(self, win_text, **kwargs):
        super().__init__(**kwargs)
        self.title = "Mivvvy.py  WINNER"
        layout = BoxLayout(orientation='vertical')
        title_label = Label(text="!!!! CONGRATULATIONS !!!!!")
        layout.add_widget(title_label)
        informative_label = Label(text="© MIZOGG & Mne 2023")
        layout.add_widget(informative_label)
        detail_label = TextInput(text=win_text, readonly=True)
        layout.add_widget(detail_label)
        ok_button = Button(text="OK", on_release=self.dismiss)
        layout.add_widget(ok_button)
        self.content = layout
        self.size_hint = (None, None)
        self.size = (600, 400)

class MivvvyApp(App):
    start_hex = NumericProperty(0)
    end_hex = NumericProperty(0)
    value_edit_hex = StringProperty("")
    btc_address_edit = StringProperty("")
    found_keys_scanned_edit = NumericProperty(0)
    total_keys_scanned_edit = NumericProperty(0)
    keys_per_sec_edit = StringProperty("")
    total_time_edit = StringProperty("")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.start_time = time.time()
        self.threads = []
        self.scanning = False
        self.stop_flag = threading.Event()

    def build(self):
        self.order = ''
        self.num_cpus = 1
        self.progress_value = 0
        self.progress_max = 100
        layout = BoxLayout(orientation='vertical')

        self.title_label = Label(text='[size=24][color=#FF0000]❤️ Good Luck and Happy Hunting Mizogg & Mne ❤️[/color][/size]', markup=True, font_name='DejaVuSans')
        layout.add_widget(self.title_label)

        header_image = Image(source='mizogg.png', size_hint_y=None, height=100)
        layout.add_widget(header_image)

        order_layout = BoxLayout(orientation='horizontal')
        order_label = Label(text='[b][color=0000FF][size=18]Order of Scan: [/size][/color][/b]', markup=True)

        order_layout.add_widget(order_label)
        self.random_button = RoundedToggleButton(text='Random', on_release=self.on_order_random)
        self.random_button.state = 'normal'
        order_layout.add_widget(self.random_button)
        self.sequence_button = RoundedToggleButton(text='Sequence', on_release=self.on_order_sequence)
        self.sequence_button.state = 'normal'
        order_layout.add_widget(self.sequence_button)
        layout.add_widget(order_layout)
        
        start_layout = BoxLayout(orientation='horizontal')
        start_label = Label(text='Start Hexadecimal Value set to puzzle 66:')
        start_layout.add_widget(start_label)
        self.start_edit = TextInput(text='20000000000000000')
        self.start_edit.bind(on_text_validate=self.on_start_hex_changed)
        start_layout.add_widget(self.start_edit)
        layout.add_widget(start_layout)

        end_layout = BoxLayout(orientation='horizontal')
        end_label = Label(text='End Hexadecimal Value set to puzzle 66:')
        end_layout.add_widget(end_label)
        self.end_edit = TextInput(text='3ffffffffffffffff')
        self.end_edit.bind(on_text_validate=self.on_end_hex_changed)
        end_layout.add_widget(self.end_edit)
        layout.add_widget(end_layout)

        hex_layout = BoxLayout(orientation='horizontal')
        hex_label = Label(text='Current HEX value :')
        hex_layout.add_widget(hex_label)
        self.value_edit_hex_label = Label(text='', font_size=sp(16), bold=True, color=[0, 1, 0, 1])
        hex_layout.add_widget(self.value_edit_hex_label)
        layout.add_widget(hex_layout)

        btc_address_layout = BoxLayout(orientation='horizontal')
        btc_address_label = Label(text='Compressed Bitcoin address:')
        btc_address_layout.add_widget(btc_address_label)
        self.btc_address_edit_label = Label(text='', font_size=sp(16), bold=True, color=[0, 1, 0, 1])
        btc_address_layout.add_widget(self.btc_address_edit_label)
        layout.add_widget(btc_address_layout)
        
        btcu_address_layout = BoxLayout(orientation='horizontal')
        btcu_address_label = Label(text='Uncompressed Bitcoin address:')
        btcu_address_layout.add_widget(btcu_address_label)
        self.btcu_address_edit_label = Label(text='', font_size=sp(16), bold=True, color=[0, 1, 0, 1])
        btcu_address_layout.add_widget(self.btcu_address_edit_label)
        layout.add_widget(btcu_address_layout)

        keys_layout = BoxLayout(orientation='horizontal')
        found_keys_scanned_label = Label(text='Found')
        keys_layout.add_widget(found_keys_scanned_label)
        self.found_keys_scanned_edit_label = Label(text='0')
        keys_layout.add_widget(self.found_keys_scanned_edit_label)
        total_keys_scanned_label = Label(text='Total keys:')
        keys_layout.add_widget(total_keys_scanned_label)
        self.total_keys_scanned_edit_label = Label(text='0')
        keys_layout.add_widget(self.total_keys_scanned_edit_label)
        keys_per_sec_label = Label(text='Keys per/sec:')
        keys_layout.add_widget(keys_per_sec_label)
        self.keys_per_sec_edit_label = Label(text='')
        keys_layout.add_widget(self.keys_per_sec_edit_label)
        total_time_label = Label(text='Total Time:')
        keys_layout.add_widget(total_time_label)
        self.total_time_edit_label = Label(text='')
        keys_layout.add_widget(self.total_time_edit_label)
        layout.add_widget(keys_layout)

        self.progress_bar = CustomProgressBar(max=self.progress_max)
        layout.add_widget(self.progress_bar)

        self.information_label = Label(text=mizogg)
        layout.add_widget(self.information_label)

        start_button = RoundedToggleButton(text='Start Scanning', on_release=self.toggle_scanning)
        layout.add_widget(start_button)
        self.start_button = start_button

        stop_button = RoundedToggleButton(text='Stop Scanning', on_release=self.stop_recovery)
        layout.add_widget(stop_button)
        self.stop_button = stop_button

        return layout

    def on_order_random(self, instance):
        if instance.state == 'down':
            self.order = 'random'
            self.sequence_button.state = 'normal'

    def on_order_sequence(self, instance):
        if instance.state == 'down':
            self.order = 'sequence'
            self.random_button.state = 'normal'

    def on_start_hex_changed(self, instance):
        try:
            self.start_hex = int(self.start_edit.text, 16)
            self.update_progress()
        except ValueError:
            self.start_edit.text = str(self.start_hex)

    def on_end_hex_changed(self, instance):
        try:
            self.end_hex = int(self.end_edit.text, 16)
            self.update_progress()
        except ValueError:
            self.end_edit.text = str(self.end_hex)
    
    def toggle_scanning(self, instance):
        if instance.state == 'down':
            self.start_recovery(instance)
        else:
            instance.state = 'normal'
            self.stop_recovery(self.stop_button)
            
    @mainthread
    def on_result(self, found_data):
        self.found_keys_scanned_edit_label.text = str(int(self.found_keys_scanned_edit_label.text) + 1)
        Clock.schedule_once(lambda dt: self.show_winner_dialog(found_data))

    def show_winner_dialog(self, found_data):
        winner_dialog = WinnerDialog(win_text=found_data)
        winner_dialog.open()

    @mainthread
    def on_progress(self, keys_generated, keys_per_sec, current_pvk, btc_address, btcu_address):
        current_time = time.time()
        if self.start_time is not None and keys_generated > 0:
            elapsed_time = current_time - self.start_time
            total_time_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
            self.total_time_edit_label.text = total_time_str

        self.total_keys_scanned_edit_label.text = str(keys_generated)

        dict_suffix = {0: 'key', 1: 'Kkey/s', 2: 'Mkey/s', 3: 'Gkey/s', 4: 'Tkey/s', 5: 'Pkey/s', 6: 'Ekeys/s'} 
        keys_per_sec *= 1.0 
        idx = 0 
        for ii in range(len(dict_suffix) - 1): 
            if int(keys_per_sec / 1000) > 0: 
                idx += 1 
                keys_per_sec /= 1000 
            else: 
                break 
        
        if keys_generated > 0:
            self.keys_per_sec_edit_label.text = f"{keys_per_sec:.2f} {dict_suffix[idx]}"
        else:
            self.keys_per_sec_edit_label.text = ""

        self.value_edit_hex_label.text = hex(current_pvk)
        self.btc_address_edit_label.text = btc_address
        self.btcu_address_edit_label.text = btcu_address


    def update_ui(self, dt):
        if self.scanning:
            keys_generated = sum(thread.found_count for thread in self.threads)
            keys_per_sec = keys_generated / (time.time() - self.start_time)
            current_pvk = self.start_hex + keys_generated
            btc_address = ''
            btcu_address = '' 
            self.on_progress(keys_generated, keys_per_sec, current_pvk, btc_address, btcu_address)

    def start_recovery(self, instance):
        self.start_time = time.time()
        for thread in self.threads:
            Clock.unschedule(thread.generate_keys_and_callback)
        self.threads = []
        try:
            self.start_hex = int(self.start_edit.text, 16)
            self.end_hex = int(self.end_edit.text, 16)
        except ValueError:
            return

        if self.end_hex < self.start_hex:
            error_range = f'\n\n !!!!!  ERROR !!!!!! \n Your Start HEX {self.start_edit.text} is MORE that your Stop HEX {self.end_edit.text}'
            self.handle_results(error_range)
        else:
            self.stop_flag.clear()

            for thread in self.threads:
                Clock.unschedule(thread.generate_keys_and_callback)
            self.start_button.state = 'down'
            self.stop_button.disabled = False
            self.threads = []
            self.scanning = True
            self.progress_bar.max = 10000
            self.progress_bar.value = 0
            self.update_progress()

            thread = KeyGenerationThread(self.start_hex, self.end_hex, self.order, self.progress_bar, self.on_progress, self.on_result, self.stop_flag)
            self.threads.append(thread)
            thread.start()

            Clock.schedule_interval(self.update_ui, 0.1)

    def stop_recovery(self, instance):
        self.stop_flag.set()

        for thread in self.threads:
            thread.stop()

        for thread in self.threads:
            thread.join()
        self.start_button.state = 'normal'
        self.stop_button.disabled = True
        self.threads = []
        self.scanning = False
        self.update_progress()
        self.handle_results('Recovery Stopped')
        Clock.unschedule(self.update_ui)


    def handle_results(self, result):
        self.information_label.text = result

    def update_progress(self):
        if self.scanning:
            current_step = (self.progress_value * self.progress_max) // 100
            self.progress_bar.value = current_step

if __name__ == '__main__':
    MivvvyApp().run()
