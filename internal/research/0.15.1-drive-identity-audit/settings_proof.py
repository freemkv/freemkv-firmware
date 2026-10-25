"""Executable DESIGN proof. In-memory transport only; not production admission.

Demonstrates typed settings planning and the existing migration stage rules.
No device access, no supported UD02 conversion, no production filter changes.
"""
from dataclasses import dataclass
import unittest


@dataclass(frozen=True)
class Hardware:
    scheme: str
    family: str
    complete: bool = True


@dataclass(frozen=True)
class Value:
    codec: str
    value: object


@dataclass(frozen=True)
class Requirement:
    key: str
    codec: str
    value: object


@dataclass(frozen=True)
class Rule:
    key: str
    source_codec: str
    target_codec: str
    parameter: int
    audited: bool


@dataclass(frozen=True)
class Change:
    key: str
    parameter: int
    before: int
    after: int


class Blocked(Exception):
    pass


# One existing migration, represented as a rule rather than a special branch.
# The executor never assumes all settings use this parameter or codec.
STARTUP = Rule('startup.word', 'pioneer.a0.u16', 'pioneer.a0.u16', 0x9f, True)


def prepare(source_hw, target_hw, current, requirements, rules):
    if (not source_hw.complete or not target_hw.complete
            or source_hw.scheme != target_hw.scheme
            or source_hw.family != target_hw.family):
        raise Blocked('hardware_incompatible_or_unknown')
    if requirements is None:
        raise Blocked('settings_unresolved')
    keys, parameters, changes = set(), set(), []
    for required in requirements:
        if required.key in keys:
            raise Blocked('conflicting_requirements')
        keys.add(required.key)
        observed = current.get(required.key)
        if observed is None:
            raise Blocked('required_setting_unreadable')
        for codec, value in [(observed.codec, observed.value), (required.codec, required.value)]:
            if codec == 'pioneer.a0.u16':
                valid = isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xffff
            elif codec == 'audit.phase':
                valid = value in ('word0=A', 'word0=B')
            else:
                valid = False
            if not valid:
                raise Blocked('setting_codec_or_value_unrecognized')
        if observed.codec == required.codec and observed.value == required.value:
            continue
        matches = [rule for rule in rules if rule.audited and rule.key == required.key
                   and rule.source_codec == observed.codec
                   and rule.target_codec == required.codec]
        if len(matches) != 1:
            raise Blocked('settings_conversion_unavailable_or_ambiguous')
        rule = matches[0]
        if (not isinstance(observed.value, int) or isinstance(observed.value, bool)
                or not isinstance(required.value, int) or isinstance(required.value, bool)
                or not 0 <= observed.value <= 0xffff or not 0 <= required.value <= 0xffff
                or not 0 <= rule.parameter < 0x400 or rule.parameter in parameters):
            raise Blocked('invalid_or_overlapping_setting')
        parameters.add(rule.parameter)
        changes.append(Change(required.key, rule.parameter, observed.value, required.value))
    return tuple(changes)


class MemoryTransport:
    def __init__(self, values, fail_after_write=None):
        self.values = dict(values)
        self.events = []
        self.fail_after_write = fail_after_write

    def read(self, parameter):
        self.events.append(('read', parameter))
        return self.values[parameter]

    def write(self, parameter, value):
        self.events.append(('write', parameter, value))
        self.values[parameter] = value
        if self.fail_after_write == parameter:
            self.fail_after_write = None
            raise RuntimeError('write result uncertain')


def execute(changes, transport, flash):
    # All values revalidated before the first write. No retries.
    originals = {c.parameter: transport.read(c.parameter) for c in changes}
    if any(originals[c.parameter] != c.before for c in changes):
        raise Blocked('source_binding_changed')
    attempted = []
    firmware_started = False

    def mark_firmware_started():
        nonlocal firmware_started
        firmware_started = True

    try:
        for change in changes:
            attempted.append(change.parameter)
            transport.write(change.parameter, change.after)
            if transport.read(change.parameter) != change.after:
                raise RuntimeError('setting readback mismatch')
        flash(mark_firmware_started)
        if any(transport.read(change.parameter) != change.after for change in changes):
            raise RuntimeError('target setting changed during flash')
        return 'verified_settings_and_flash_callback_completed'
    except Exception:
        if firmware_started:
            return 'failed_after_firmware_entry_no_blind_rollback'
        for parameter in reversed(attempted):
            try:
                transport.write(parameter, originals[parameter])
                if transport.read(parameter) != originals[parameter]:
                    return 'rollback_uncertain'
            except Exception:
                return 'rollback_uncertain'
        return 'failed_before_firmware_originals_restored'


class Proof(unittest.TestCase):
    hardware = Hardware('proof.hardware.v1', 'same-platform')

    def plan(self, value=0xffff, target=0xff01, rules=(STARTUP,)):
        return prepare(self.hardware, self.hardware,
                       {'startup.word': Value('pioneer.a0.u16', value)},
                       [Requirement('startup.word', 'pioneer.a0.u16', target)], rules)

    def test_hardware_mismatch_cannot_be_overridden_by_a_rule(self):
        with self.assertRaisesRegex(Blocked, 'hardware'):
            prepare(self.hardware, Hardware('proof.hardware.v1', 'other'), {}, [], [STARTUP])

    def test_unknown_and_different_scheme_never_match(self):
        for other in [Hardware('proof.hardware.v1', 'same-platform', False),
                      Hardware('proof.hardware.v2', 'same-platform')]:
            with self.assertRaises(Blocked):
                prepare(self.hardware, other, {}, [], [])

    def test_compatible_settings_need_no_conversion(self):
        self.assertEqual(self.plan(value=0xff01, rules=()), ())

    def test_missing_conversion_blocks_matching_hardware(self):
        with self.assertRaisesRegex(Blocked, 'conversion_unavailable'):
            self.plan(rules=())

    def test_missing_requirement_or_read_blocks(self):
        for requirements in [None, [Requirement('unread', 'pioneer.a0.u16', 1)]]:
            with self.assertRaises(Blocked):
                prepare(self.hardware, self.hardware, {}, requirements, [STARTUP])

    def test_9f_uses_source_value_and_target_requirement(self):
        plan = self.plan()
        io = MemoryTransport({0x9f: 0xffff})
        flashed = []
        def flash(start):
            self.assertEqual(io.values[0x9f], 0xff01)
            start()
            flashed.append(True)
        self.assertEqual(execute(plan, io, flash), 'verified_settings_and_flash_callback_completed')
        self.assertEqual(io.events, [('read', 0x9f), ('write', 0x9f, 0xff01),
                                     ('read', 0x9f), ('read', 0x9f)])
        self.assertTrue(flashed)

    def test_multiple_entries_are_generic_and_read_before_any_write(self):
        second = Rule('proof.second', 'pioneer.a0.u16', 'pioneer.a0.u16', 0x123, True)
        plan = prepare(self.hardware, self.hardware,
                       {'startup.word': Value('pioneer.a0.u16', 0xffff),
                        'proof.second': Value('pioneer.a0.u16', 2)},
                       [Requirement('proof.second', 'pioneer.a0.u16', 3),
                        Requirement('startup.word', 'pioneer.a0.u16', 0xff01)],
                       [STARTUP, second])
        io = MemoryTransport({0x9f: 0xffff, 0x123: 2})
        execute(plan, io, lambda start: start())
        self.assertEqual(io.events[:2], [('read', 0x123), ('read', 0x9f)])

    def test_partial_setting_failure_restores_in_reverse_order_without_flash(self):
        plan = (Change('first', 0x9f, 1, 2), Change('second', 0x123, 3, 4))
        io = MemoryTransport({0x9f: 1, 0x123: 3}, fail_after_write=0x123)
        self.assertEqual(execute(plan, io, lambda _: self.fail('must not flash')),
                         'failed_before_firmware_originals_restored')
        self.assertEqual(io.values, {0x9f: 1, 0x123: 3})
        self.assertEqual([e[1] for e in io.events if e[0] == 'write'], [0x9f, 0x123, 0x123, 0x9f])

    def test_no_rollback_after_firmware_entry(self):
        io = MemoryTransport({0x9f: 0xffff})
        def flash(start):
            start()
            raise RuntimeError('firmware state uncertain')
        self.assertEqual(execute(self.plan(), io, flash),
                         'failed_after_firmware_entry_no_blind_rollback')
        self.assertEqual(io.values[0x9f], 0xff01)

    def test_rebinding_refuses_changed_source_before_writes(self):
        io = MemoryTransport({0x9f: 0})
        with self.assertRaisesRegex(Blocked, 'binding_changed'):
            execute(self.plan(), io, lambda _: self.fail('must not flash'))
        self.assertFalse(any(e[0] == 'write' for e in io.events))

    def test_invalid_values_are_not_compatible_even_when_equal(self):
        for value in [True, -1, 65536, None]:
            with self.assertRaises(Blocked):
                self.plan(value=value, target=value)

    def test_post_flash_setting_mismatch_never_reports_success_or_rolls_back(self):
        io = MemoryTransport({0x9f: 0xffff})
        def flash(start):
            start()
            io.values[0x9f] = 0
        self.assertEqual(execute(self.plan(), io, flash),
                         'failed_after_firmware_entry_no_blind_rollback')
        self.assertEqual(io.values[0x9f], 0)

    def test_unvalidated_motion_mapping_stays_blocked(self):
        with self.assertRaisesRegex(Blocked, 'conversion_unavailable'):
            prepare(self.hardware, self.hardware,
                    {'mechanism.phase': Value('audit.phase', 'word0=A')},
                    [Requirement('mechanism.phase', 'audit.phase', 'word0=B')], [STARTUP])

    def test_ambiguous_rules_and_duplicate_parameters_block(self):
        with self.assertRaises(Blocked):
            self.plan(rules=(STARTUP, STARTUP))
        alias = Rule('alias', 'pioneer.a0.u16', 'pioneer.a0.u16', 0x9f, True)
        with self.assertRaises(Blocked):
            prepare(self.hardware, self.hardware,
                    {'startup.word': Value('pioneer.a0.u16', 0),
                     'alias': Value('pioneer.a0.u16', 0)},
                    [Requirement('startup.word', 'pioneer.a0.u16', 1),
                     Requirement('alias', 'pioneer.a0.u16', 2)], [STARTUP, alias])


if __name__ == '__main__':
    unittest.main()
