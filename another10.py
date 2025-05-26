import xml.etree.ElementTree as ET
import random
import time
import hashlib
import json
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import matplotlib.pyplot as plt

def parse_sumo_fcd(fcd_file):
    tree = ET.parse(fcd_file)
    root = tree.getroot()
    mobility_data = {}
    for timestep in root.findall('timestep'):
        time_ = float(timestep.get('time'))
        vehicles = []
        for v in timestep.findall('vehicle'):
            vehicles.append({
                'id': v.get('id'),
                'x': float(v.get('x')),
                'y': float(v.get('y')),
                'speed': float(v.get('speed')),
            })
        mobility_data[time_] = vehicles
    return mobility_data

class Vehicle:
    def __init__(self, vehicle_id, speed, position):
        self.id = vehicle_id
        self.speed = speed
        self.position = position
        self.salt = "vanet" + str(random.random())
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def generate_message(self):
        message = {
            "vehicle_id": self.id,
            "speed": self.speed,
            "position": self.position,
            "timestamp": time.time()
        }
        message_bytes = json.dumps(message, sort_keys=True).encode()
        hashes, hash_times = self.hash_message(message_bytes)
        signature, sig_time = self.sign_message(message_bytes)
        return message, message_bytes, hashes, hash_times, signature, sig_time

    def hash_message(self, message_bytes):
        hashes = {}
        hash_times = {}
        salt_bytes = self.salt.encode()
        for algo in ["sha256", "md5", "sha1", "blake2b", "sha3_256"]:
            start = time.time()
            if algo == "sha256":
                h = hashlib.sha256(message_bytes + salt_bytes).hexdigest()
            elif algo == "md5":
                h = hashlib.md5(message_bytes + salt_bytes).hexdigest()
            elif algo == "sha1":
                h = hashlib.sha1(message_bytes + salt_bytes).hexdigest()
            elif algo == "blake2b":
                h = hashlib.blake2b(message_bytes + salt_bytes).hexdigest()
            elif algo == "sha3_256":
                h = hashlib.sha3_256(message_bytes + salt_bytes).hexdigest()
            hashes[algo] = h
            hash_times[algo] = time.time() - start
        return hashes, hash_times

    def sign_message(self, message_bytes):
        start = time.time()
        signature = self.private_key.sign(
            message_bytes + self.salt.encode(),
            ec.ECDSA(crypto_hashes.SHA256())
        )
        sig_time = time.time() - start
        return signature, sig_time

    def verify_signature(self, message_bytes, signature, sender_pubkey, sender_salt):
        try:
            sender_pubkey.verify(
                signature,
                message_bytes + sender_salt.encode(),
                ec.ECDSA(crypto_hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    def check_integrity(self, message_bytes, hashes, sender_salt):
        salt_bytes = sender_salt.encode()
        for algo in ["sha256", "md5", "sha1", "blake2b", "sha3_256"]:
            if algo == "sha256":
                h = hashlib.sha256(message_bytes + salt_bytes).hexdigest()
            elif algo == "md5":
                h = hashlib.md5(message_bytes + salt_bytes).hexdigest()
            elif algo == "sha1":
                h = hashlib.sha1(message_bytes + salt_bytes).hexdigest()
            elif algo == "blake2b":
                h = hashlib.blake2b(message_bytes + salt_bytes).hexdigest()
            elif algo == "sha3_256":
                h = hashlib.sha3_256(message_bytes + salt_bytes).hexdigest()
            if hashes[algo] != h:
                return False
        return True

    def receive_message(self, message, message_bytes, hashes, signature, sender_pubkey, sender_salt, replay_cache, known_id_pubkey_map=None, verbose=False):
        msg_time = message.get("timestamp", 0)
        replay_key = (message.get("vehicle_id"), msg_time)
        replay_detected = replay_key in replay_cache
        if not replay_detected:
            replay_cache.add(replay_key)

        integrity = self.check_integrity(message_bytes, hashes, sender_salt)
        signature_ok = self.verify_signature(message_bytes, signature, sender_pubkey, sender_salt)
        sybil_attack = False
        if known_id_pubkey_map is not None:
            expected_pubkey = known_id_pubkey_map.get(message['vehicle_id'])
            if expected_pubkey and sender_pubkey != expected_pubkey:
                sybil_attack = True
        tampering = signature_ok and not integrity
        security_failure = not integrity or not signature_ok or replay_detected or sybil_attack or tampering

        delay = None
        if not security_failure:
            receive_time = time.time()
            delay = receive_time - msg_time
        if verbose:
            print("\n" + "="*70)
            print(f"Vehicle {self.id} received message from Vehicle {message['vehicle_id']}:")
            print(f"  Speed: {message['speed']}")
            print(f"  Position: {message['position']}")
            print(f"  Timestamp: {msg_time}")
            print("  Hashes:")
            for k, v in hashes.items():
                print(f"    {k}: {v}")
            print(f"  Digital Signature: {signature.hex()[:40]}...")
            print(f"  Integrity Check: {'VALID' if integrity else 'INVALID'}")
            print(f"  Signature Check: {'VALID' if signature_ok else 'INVALID'}")
            print(f"  Replay Attack Detected: {'YES' if replay_detected else 'NO'}")
            if sybil_attack:
                print(">>> SYBIL ATTACK DETECTED!")
            if tampering:
                print(">>> DATA TAMPERING DETECTED!")
            if security_failure:
                print(">>> WARNING: Message failed security checks!\n")
            else:
                print(">>> Message is authentic, untampered, and fresh.\n")
            print("="*70)
        return {
            "integrity": integrity,
            "signature_ok": signature_ok,
            "replay": replay_detected,
            "sybil": sybil_attack,
            "tampering": tampering,
            "delay": delay
        }

def main():
    print("STARTING SIMULATION")
    mobility_data = parse_sumo_fcd('simple_fcd.xml')
    vehicle_ids = set()
    for vehicles in mobility_data.values():
        for v in vehicles:
            vehicle_ids.add(v['id'])
    vehicles = [Vehicle(vid, 0, (0, 0)) for vid in vehicle_ids]
    vehicles_dict = {v.id: v for v in vehicles}
    known_id_pubkey_map = {v.id: v.public_key for v in vehicles}
    replay_cache = set()
    timesteps = sorted(mobility_data.keys())

    packets_sent = 0
    packets_received = 0
    total_data_sent = 0
    total_data_received = 0
    delay_values = []
    packet_timestamps = []
    pdr_values = []
    time_points = []
    security_events = []

    simulation_start_time = time.time()
    printed = 0
    max_verbose = 10

    for time_step in timesteps:
        # Update vehicle state
        for vdata in mobility_data[time_step]:
            vid = vdata['id']
            vehicle = vehicles_dict[vid]
            vehicle.speed = vdata['speed']
            vehicle.position = (vdata['x'], vdata['y'])

        # Message exchanges
        for sender in vehicles:
            message, message_bytes, hashes, _, signature, _ = sender.generate_message()
            packets_sent += len(vehicles) - 1
            total_data_sent += len(message_bytes) * (len(vehicles) - 1)
            for receiver in vehicles:
                if receiver.id == sender.id:
                    continue
                result = receiver.receive_message(
                    message, message_bytes, hashes, signature,
                    sender.public_key, sender.salt, replay_cache, known_id_pubkey_map,
                    verbose=(printed < max_verbose)
                )
                if printed < max_verbose:
                    printed += 1
                if (result["integrity"] and result["signature_ok"] and
                    not result["replay"] and not result["sybil"] and not result["tampering"]):
                    packets_received += 1
                    total_data_received += len(message_bytes)
                    delay = result["delay"]
                    delay_values.append(delay)
                    packet_timestamps.append(time.time())
                    current_pdr = (packets_received / packets_sent) * 100 if packets_sent else 0
                    pdr_values.append(current_pdr)
                    time_points.append(time_step)
                else:
                    security_events.append({
                        "time": time.time(),
                        "type": "Security Failure",
                        "sender": message.get("vehicle_id"),
                        "receiver": receiver.id
                    })

    simulation_end_time = time.time()
    simulation_duration = simulation_end_time - simulation_start_time
    pdr = (packets_received / packets_sent) * 100 if packets_sent else 0
    avg_delay = (sum(delay_values) / packets_received) if packets_received else 0
    throughput = (total_data_received / simulation_duration) if simulation_duration else 0

    print("\n" + "="*50 + " Simulation Report " + "="*50)
    print(f"Total Packets Sent: {packets_sent}")
    print(f"Total Packets Received: {packets_received}")
    print(f"Packet Delivery Ratio (PDR): {pdr:.2f}%")
    print(f"Average End-to-End Delay: {avg_delay:.6f} seconds")
    print(f"Total Data Received: {total_data_received} bytes")
    print(f"Simulation Duration: {simulation_duration:.2f} seconds")
    print(f"Throughput: {throughput:.2f} bytes/second")

    print("\n" + "="*50 + " Security Effectiveness " + "="*50)
    if security_events:
        print("Security Events Detected:")
        for event in security_events[:10]:
            print(f"  Time: {event['time']:.2f}, Type: {event['type']}, Sender: {event['sender']}, Receiver: {event['receiver']}")
        print(f"Total Security Events: {len(security_events)}")
    else:
        print("No security events detected during the simulation.")

    # Plotting
    plt.figure(figsize=(12, 6))
    # Plot PDR
    plt.subplot(1, 2, 1)
    plt.plot(time_points, pdr_values, marker='o', linestyle='-')
    plt.xlabel("Simulation Time")
    plt.ylabel("Packet Delivery Ratio (%)")
    plt.title("PDR over Time")
    plt.grid(True)
    # Plot End-to-End Delay
    plt.subplot(1, 2, 2)
    plt.scatter(packet_timestamps, delay_values, marker='o', s=10)
    plt.xlabel("Reception Time")
    plt.ylabel("End-to-End Delay (s)")
    plt.title("End-to-End Delay of Received Packets")
    plt.grid(True)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()
