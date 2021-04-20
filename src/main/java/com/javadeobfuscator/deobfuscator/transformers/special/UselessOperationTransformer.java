package com.javadeobfuscator.deobfuscator.transformers.special;

import java.util.ListIterator;
import java.util.concurrent.atomic.LongAdder;

import com.javadeobfuscator.deobfuscator.config.TransformerConfig;
import com.javadeobfuscator.deobfuscator.exceptions.WrongTransformerException;
import com.javadeobfuscator.deobfuscator.iterablematcher.IterableInsnMatcher;
import com.javadeobfuscator.deobfuscator.iterablematcher.IterableStep;
import com.javadeobfuscator.deobfuscator.iterablematcher.NoSideEffectLoad1SlotStep;
import com.javadeobfuscator.deobfuscator.iterablematcher.NoSideEffectLoad2SlotStep;
import com.javadeobfuscator.deobfuscator.iterablematcher.SimpleStep;
import com.javadeobfuscator.deobfuscator.iterablematcher.StackStep;
import com.javadeobfuscator.deobfuscator.transformers.Transformer;
import com.javadeobfuscator.deobfuscator.utils.Utils;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;

public class UselessOperationTransformer extends Transformer<TransformerConfig> {

    /*
    Naming scheme:
     - c1  - no side effect load 1 slot
     - c2  - no side effect load 2 slot
     - p   - pop
     - p2  - pop2
     - s   - stack store
     - l   - stack load
     - d   - dup
     - d2  - dup2
     - dx1 - dup_x1
     - dx1 - dup_x2
     - w   - swap
     */

    private final IterableStep<?> c1c1w_1 = new NoSideEffectLoad1SlotStep(true);
    private final IterableStep<?> c1c1w_2 = new NoSideEffectLoad1SlotStep(true);
    private final IterableInsnMatcher c1c1w = new IterableInsnMatcher(it -> {
        it.addStep(c1c1w_1);
        it.addStep(c1c1w_2);
        it.addStep(new SimpleStep(SWAP));
    });
    private final IterableStep<?> c2d2_1 = new NoSideEffectLoad2SlotStep(false);
    private final IterableInsnMatcher c2d2 = new IterableInsnMatcher(it -> {
        it.addStep(c2d2_1);
        it.addStep(new SimpleStep(DUP2));
    });

    private final IterableStep<?> c1c1dx1_1 = new NoSideEffectLoad1SlotStep(false);
    private final IterableStep<?> c1c1dx1_2 = new NoSideEffectLoad1SlotStep(false);
    private final IterableInsnMatcher c1c1dx1 = new IterableInsnMatcher(it -> {
        it.addStep(c1c1dx1_1);
        it.addStep(c1c1dx1_2);
        it.addStep(new SimpleStep(DUP_X1));
    });

    private final IterableStep<?> c1c1c1dx2_1 = new NoSideEffectLoad1SlotStep(false);
    private final IterableStep<?> c1c1c1dx2_2 = new NoSideEffectLoad1SlotStep(false);
    private final IterableStep<?> c1c1c1dx2_3 = new NoSideEffectLoad1SlotStep(false);
    private final IterableInsnMatcher c1c1c1dx2 = new IterableInsnMatcher(it -> {
        it.addStep(c1c1c1dx2_1);
        it.addStep(c1c1c1dx2_2);
        it.addStep(c1c1c1dx2_3);
        it.addStep(new SimpleStep(DUP_X2));
    });

    private final IterableStep<?> c2c1dx2_1 = new NoSideEffectLoad2SlotStep(false);
    private final IterableStep<?> c2c1dx2_2 = new NoSideEffectLoad1SlotStep(false);
    private final IterableInsnMatcher c2c1dx2 = new IterableInsnMatcher(it -> {
        it.addStep(c2c1dx2_1);
        it.addStep(c2c1dx2_2);
        it.addStep(new SimpleStep(DUP_X2));
    });
    
    private final IterableInsnMatcher c1p = new IterableInsnMatcher(it -> {
        it.addStep(new NoSideEffectLoad1SlotStep(true));
        it.addStep(new SimpleStep(POP));
    });
    private final IterableInsnMatcher c2p = new IterableInsnMatcher(it -> {
        it.addStep(new NoSideEffectLoad2SlotStep(true));
        it.addStep(new SimpleStep(POP2));
    });

    private final IterableInsnMatcher c1sl = new IterableInsnMatcher();
    private final IterableStep<?> c1sl_1 = c1sl.addStep(new NoSideEffectLoad1SlotStep(false));
    private final StackStep c1sl_2 = c1sl.addStep(new StackStep(false, false));
    private final StackStep c1sl_3 = c1sl.addStep(new StackStep(true, false));

    private final IterableInsnMatcher c2sl = new IterableInsnMatcher();
    private final IterableStep<?> c2sl_1 = c2sl.addStep(new NoSideEffectLoad2SlotStep(false));
    private final StackStep c2sl_2 = c2sl.addStep(new StackStep(false, true));
    private final StackStep c2sl_3 = c2sl.addStep(new StackStep(true, true));

    private final IterableInsnMatcher c1c1p2 = new IterableInsnMatcher(it -> {
        it.addStep(new NoSideEffectLoad1SlotStep(true));
        it.addStep(new NoSideEffectLoad1SlotStep(true));
        it.addStep(new SimpleStep(POP2));
    });
    private final IterableInsnMatcher doubleINEG = new IterableInsnMatcher(it -> {
        it.addStep(new SimpleStep(INEG));
        it.addStep(new SimpleStep(INEG));
    });
    private final IterableInsnMatcher doubleLNEG = new IterableInsnMatcher(it -> {
        it.addStep(new SimpleStep(LNEG));
        it.addStep(new SimpleStep(LNEG));
    });
    private final IterableInsnMatcher dp2 = new IterableInsnMatcher(it -> {
        it.addStep(new SimpleStep(DUP));
        it.addStep(new SimpleStep(POP2));
    });

    @Override
    public boolean transform() throws Throwable, WrongTransformerException {
        LongAdder counter = new LongAdder();
        LongAdder counterNop = new LongAdder();
        LongAdder counterSimplified = new LongAdder();
        classNodes().forEach(classNode -> classNode.methods.stream().filter(Utils::notAbstractOrNative).forEach(methodNode -> {
            boolean edit;
            try {
                do {
                    edit = false;
                    ListIterator<AbstractInsnNode> it = methodNode.instructions.iterator();
                    while (it.hasNext()) {
                        if (it.next().getOpcode() == NOP) {
                            it.remove();
                            counterNop.increment();
                            edit = true;
                        }
                    }
                    edit = removeAll(c1p, methodNode.instructions, counter, edit);
                    edit = removeAll(c2p, methodNode.instructions, counter, edit);
                    edit = removeAll(c1c1p2, methodNode.instructions, counter, edit);
                    edit = removeAll(doubleINEG, methodNode.instructions, counter, edit);
                    edit = removeAll(doubleLNEG, methodNode.instructions, counter, edit);

                    it = methodNode.instructions.iterator();
                    while (it.hasNext()) {
                        if (c1sl.match(it)) {
                            int v1 = c1sl_2.getCaptured().var;
                            int v2 = c1sl_3.getCaptured().var;
                            if (v1 == v2) {
                                c1sl.addReplacement(c1sl_3, c1sl_1.getCaptured().clone(null));
                                if (!c1sl.replace(it)) {
                                    throw new IllegalStateException("c1sl");
                                }
                                counterSimplified.increment();
                                edit = true;
                            }
                            c1sl.reset();
                        }
                    }
                    it = methodNode.instructions.iterator();
                    while (it.hasNext()) {
                        if (c2sl.match(it)) {
                            int v1 = c2sl_2.getCaptured().var;
                            int v2 = c2sl_3.getCaptured().var;
                            if (v1 == v2) {
                                c2sl.addReplacement(c2sl_3, c2sl_1.getCaptured().clone(null));
                                if (!c2sl.replace(it)) {
                                    throw new IllegalStateException("c2sl");
                                }
                                counterSimplified.increment();
                                edit = true;
                            }
                            c2sl.reset();
                        }
                    }
                    it = methodNode.instructions.iterator();
                    while (it.hasNext()) {
                        if (dp2.match(it)) {
                            dp2.setRemoval(0);
                            dp2.setReplacement(1, new InsnNode(POP));
                            if (!c2sl.replace(it)) {
                                throw new IllegalStateException("dp2");
                            }
                            counterSimplified.increment();
                            edit = true;
                            c2sl.reset();
                        }
                    }
                    it = methodNode.instructions.iterator();
                    while (it.hasNext()) {
                        if (c1c1w.match(it)) {
                            c1c1w.addReplacement(c1c1w_1, c1c1w_2.getCaptured().clone(null));
                            c1c1w.addReplacement(c1c1w_2, c1c1w_1.getCaptured().clone(null));
                            c1c1w.setRemoval(2);
                            if (!c1c1w.replace(it)) {
                                throw new IllegalStateException("c1c1w");
                            }
                            counterSimplified.increment();
                            edit = true;
                            c1c1w.reset();
                        }
                    }
                    it = methodNode.instructions.iterator();
                    while (it.hasNext()) {
                        if (c1c1dx1.match(it)) {
                            c1c1dx1.addReplacement(c1c1dx1_1, c1c1dx1_2.getCaptured().clone(null));
                            c1c1dx1.addReplacement(c1c1dx1_2, c1c1dx1_1.getCaptured().clone(null));
                            c1c1dx1.setReplacement(2, c1c1dx1_2.getCaptured().clone(null));
                            if (!c1c1dx1.replace(it)) {
                                throw new IllegalStateException("c1c1dx1");
                            }
                            counterSimplified.increment();
                            edit = true;
                            c1c1dx1.reset();
                        }
                    }
                    it = methodNode.instructions.iterator();
                    while (it.hasNext()) {
                        if (c2d2.match(it)) {
                            c2d2.setReplacement(1, c2d2_1.getCaptured().clone(null));
                            if (!c2d2.replace(it)) {
                                throw new IllegalStateException("c2d2");
                            }
                            counterSimplified.increment();
                            edit = true;
                            c2d2.reset();
                        }
                    }
                    it = methodNode.instructions.iterator();
                    while (it.hasNext()) {
                        if (c1c1c1dx2.match(it)) {
                            c1c1c1dx2.addReplacement(c1c1c1dx2_1, c1c1c1dx2_3.getCaptured().clone(null));
                            c1c1c1dx2.addReplacement(c1c1c1dx2_2, c1c1c1dx2_1.getCaptured().clone(null));
                            c1c1c1dx2.addReplacement(c1c1c1dx2_3, c1c1c1dx2_2.getCaptured().clone(null));
                            c1c1c1dx2.setReplacement(3, c1c1c1dx2_3.getCaptured().clone(null));
                            if (!c1c1c1dx2.replace(it)) {
                                throw new IllegalStateException("c1c1c1dx2");
                            }
                            counterSimplified.increment();
                            edit = true;
                            c1c1c1dx2.reset();
                        }
                    }
                    it = methodNode.instructions.iterator();
                    while (it.hasNext()) {
                        if (c2c1dx2.match(it)) {
                            c2c1dx2.addReplacement(c2c1dx2_1, c2c1dx2_2.getCaptured().clone(null));
                            c2c1dx2.addReplacement(c2c1dx2_2, c2c1dx2_1.getCaptured().clone(null));
                            c2c1dx2.setReplacement(3, c2c1dx2_1.getCaptured().clone(null));
                            if (!c2c1dx2.replace(it)) {
                                throw new IllegalStateException("c2c1dx2");
                            }
                            counterSimplified.increment();
                            edit = true;
                            c2c1dx2.reset();
                        }
                    }
                } while (edit);
            } catch (Exception ex) {
                throw new RuntimeException(classNode.name + " " + methodNode.name + " " + methodNode.desc, ex);
            }
        }));
        logger.info("Removed " + counterNop + " NOPs");
        logger.info("Removed " + counter + " useless stack operations");
        logger.info("Simplified " + counterSimplified + " stack operations");
        return counterNop.sum() > 0 || counter.sum() > 0 || counterSimplified.sum() > 0;
    }

    private static boolean removeAll(IterableInsnMatcher matcher, InsnList insns, LongAdder counter, boolean edit) {
        int count = IterableInsnMatcher.removeAll(matcher, insns);
        if (count > 0) {
            counter.add(count);
            return true;
        }
        return edit;
    }
}
