/*
 * Copyright 2017 Sam Sun <github-contact@samczsun.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.javadeobfuscator.deobfuscator.transformers.general.peephole;

import com.javadeobfuscator.deobfuscator.analyzer.AnalyzerResult;
import com.javadeobfuscator.deobfuscator.analyzer.MethodAnalyzer;
import com.javadeobfuscator.deobfuscator.analyzer.frame.*;
import com.javadeobfuscator.deobfuscator.config.TransformerConfig;
import org.objectweb.asm.tree.*;
import com.javadeobfuscator.deobfuscator.transformers.Transformer;
import com.javadeobfuscator.deobfuscator.utils.Utils;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

@TransformerConfig.ConfigOptions(configClass = ConstantFolder.Config.class)
public class ConstantFolder extends Transformer<ConstantFolder.Config> {

    @Override
    public boolean transform() throws Throwable {
        AtomicInteger folded = new AtomicInteger();
        classNodes().forEach(classNode -> {
            classNode.methods.stream().filter(methodNode -> methodNode.instructions.getFirst() != null).forEach(methodNode -> {
                int start;
                do {
                    start = folded.get();
                    AnalyzerResult result = MethodAnalyzer.analyze(classNode, methodNode);

                    Map<AbstractInsnNode, InsnList> replacements = new HashMap<>();

                    for (int i = 0; i < methodNode.instructions.size(); i++) {
                        final AbstractInsnNode ain = methodNode.instructions.get(i);
                        final int ainOpcode = ain.getOpcode();
                        opcodes:
                        switch (ain.getOpcode()) {
                            case IADD:
                            case ISUB:
                            case IMUL:
                            case IDIV:
                            case IREM:
                            case ISHL:
                            case ISHR:
                            case IUSHR:
                            case IXOR:
                            case IOR:
                            case IAND: {
                                List<Frame> frames = result.getFrames().get(ain);
                                if (frames == null) {
                                    break;
                                }
                                Set<Integer> results = new HashSet<>();
                                for (Frame frame0 : frames) {
                                    MathFrame frame = (MathFrame) frame0;
                                    if (frame.getTargets().size() != 2) {
                                        throw new RuntimeException("weird: " + frame);
                                    }
                                    Frame top = frame.getTargets().get(0);
                                    Frame bottom = frame.getTargets().get(1);
                                    if (top instanceof LdcFrame && bottom instanceof LdcFrame) {
                                        if (results.size() > 1) {
                                            break opcodes;
                                        }
                                        int bottomValue = ((Number) ((LdcFrame) bottom).getConstant()).intValue();
                                        int topValue = ((Number) ((LdcFrame) top).getConstant()).intValue();
                                        switch (ainOpcode) {
                                            case IADD:
                                                results.add(bottomValue + topValue);
                                                break;
                                            case IMUL:
                                                results.add(bottomValue * topValue);
                                                break;
                                            case IREM:
                                                results.add(bottomValue % topValue);
                                                break;
                                            case ISUB:
                                                results.add(bottomValue - topValue);
                                                break;
                                            case IDIV:
                                                results.add(bottomValue / topValue);
                                                break;
                                            case ISHL:
                                                results.add(bottomValue << topValue);
                                                break;
                                            case ISHR:
                                                results.add(bottomValue >> topValue);
                                                break;
                                            case IUSHR:
                                                results.add(bottomValue >>> topValue);
                                                break;
                                            case IXOR:
                                                results.add(bottomValue ^ topValue);
                                                break;
                                            case IOR:
                                                results.add(bottomValue | topValue);
                                                break;
                                            case IAND:
                                                results.add(bottomValue & topValue);
                                                break;
                                            default:
                                                throw new IllegalStateException("Unexpected insn: " + Utils.prettyprint(ain));
                                        }
                                    } else {
                                        break opcodes;
                                    }
                                }
                                if (results.size() == 1) {
                                    InsnList replacement = new InsnList();
                                    replacement.add(new InsnNode(POP2)); // remove existing args from stack
                                    replacement.add(Utils.getIntInsn(results.iterator().next()));
                                    replacements.put(ain, replacement);
                                    folded.getAndIncrement();
                                }
                                break;
                            }
                            case LADD:
                            case LSUB:
                            case LMUL:
                            case LDIV:
                            case LREM:
                            case LSHL:
                            case LSHR:
                            case LUSHR:
                            case LXOR:
                            case LOR:
                            case LAND: {
                                List<Frame> frames = result.getFrames().get(ain);
                                if (frames == null) {
                                    break;
                                }
                                Set<Long> results = new HashSet<>();
                                for (Frame frame0 : frames) {
                                    MathFrame frame = (MathFrame) frame0;
                                    if (frame.getTargets().size() != 2) {
                                        throw new RuntimeException("weird: " + frame);
                                    }
                                    Frame top = frame.getTargets().get(0);
                                    Frame bottom = frame.getTargets().get(1);
                                    if (top instanceof LdcFrame && bottom instanceof LdcFrame) {
                                        if (results.size() > 1) {
                                            break opcodes;
                                        }
                                        long bottomValue = ((Number) ((LdcFrame) bottom).getConstant()).longValue();
                                        long topValue = ((Number) ((LdcFrame) top).getConstant()).longValue();
                                        switch (ainOpcode) {
                                            case LADD:
                                                results.add(bottomValue + topValue);
                                                break;
                                            case LMUL:
                                                results.add(bottomValue * topValue);
                                                break;
                                            case LREM:
                                                results.add(bottomValue % topValue);
                                                break;
                                            case LSUB:
                                                results.add(bottomValue - topValue);
                                                break;
                                            case LDIV:
                                                results.add(bottomValue / topValue);
                                                break;
                                            case LSHL:
                                                results.add(bottomValue << topValue);
                                                break;
                                            case LSHR:
                                                results.add(bottomValue >> topValue);
                                                break;
                                            case LUSHR:
                                                results.add(bottomValue >>> topValue);
                                                break;
                                            case LXOR:
                                                results.add(bottomValue ^ topValue);
                                                break;
                                            case LOR:
                                                results.add(bottomValue | topValue);
                                                break;
                                            case LAND:
                                                results.add(bottomValue & topValue);
                                                break;
                                            default:
                                                throw new IllegalStateException("Unexpected insn: " + Utils.prettyprint(ain));
                                        }
                                    } else {
                                        break opcodes;
                                    }
                                }
                                if (results.size() == 1) {
                                    InsnList replacement = new InsnList();
                                    replacement.add(new InsnNode(POP2)); // remove existing args from stack
                                    replacement.add(new InsnNode(POP2)); // remove existing args from stack
                                    replacement.add(Utils.getLongInsn(results.iterator().next()));
                                    replacements.put(ain, replacement);
                                    folded.getAndIncrement();
                                }
                                break;
                            }
                            case INEG: {
                                List<Frame> frames = result.getFrames().get(ain);
                                if (frames == null) {
                                    // wat
                                    break;
                                }
                                Set<Integer> results = new HashSet<>();
                                for (Frame frame0 : frames) {
                                    MathFrame frame = (MathFrame) frame0;
                                    if (frame.getTargets().size() != 1) {
                                        throw new RuntimeException("weird: " + frame);
                                    }
                                    if (frame.getTargets().get(0) instanceof LdcFrame) {
                                        if (results.size() > 1) {
                                            break opcodes;
                                        }
                                        int value = ((Number) ((LdcFrame) frame.getTargets().get(0)).getConstant()).intValue();
                                        if (ainOpcode == INEG) {
                                            results.add(-value);
                                        } else {
                                            throw new RuntimeException();
                                        }
                                    } else {
                                        break opcodes;
                                    }
                                }
                                if (results.size() == 1) {
                                    InsnList replacement = new InsnList();
                                    replacement.add(new InsnNode(POP)); // remove existing arg from stack
                                    replacement.add(Utils.getIntInsn(results.iterator().next()));
                                    replacements.put(ain, replacement);
                                    folded.getAndIncrement();
                                }
                                break;
                            }
                            case LNEG: {
                                List<Frame> frames = result.getFrames().get(ain);
                                if (frames == null) {
                                    // wat
                                    break;
                                }
                                Set<Long> results = new HashSet<>();
                                for (Frame frame0 : frames) {
                                    MathFrame frame = (MathFrame) frame0;
                                    if (frame.getTargets().get(0) instanceof LdcFrame) {
                                        if (results.size() > 1) {
                                            break opcodes;
                                        }
                                        long value = ((Number) ((LdcFrame) frame.getTargets().get(0)).getConstant()).longValue();
                                        if (ainOpcode == LNEG) {
                                            results.add(-value);
                                        } else {
                                            throw new RuntimeException();
                                        }
                                    } else {
                                        break opcodes;
                                    }
                                }
                                if (results.size() == 1) {
                                    InsnList replacement = new InsnList();
                                    replacement.add(new InsnNode(POP2)); // remove existing arg from stack
                                    replacement.add(Utils.getLongInsn(results.iterator().next()));
                                    replacements.put(ain, replacement);
                                    folded.getAndIncrement();
                                }
                                break;
                            }
                            case TABLESWITCH: {
                                List<Frame> frames = result.getFrames().get(ain);
                                if (frames == null) {
                                    // wat
                                    break;
                                }
                                Set<Integer> results = new HashSet<>();
                                Set<LdcFrame> resultFrames = new HashSet<>();
                                for (Frame frame0 : frames) {
                                    SwitchFrame frame = (SwitchFrame) frame0;
                                    if (frame.getSwitchTarget() instanceof LdcFrame) {
                                    	resultFrames.add((LdcFrame)frame.getSwitchTarget());
                                        results.add(((Number) ((LdcFrame) frame.getSwitchTarget()).getConstant()).intValue());
                                    } else {
                                        break opcodes;
                                    }
                                }
                                if(results.size() > 1)
                                {
                                	//Impossible "infinite switch"
                                	Iterator<LdcFrame> itr = resultFrames.iterator();
                            	 	while(itr.hasNext())
                            	 	{
                            	 		LdcFrame ldcFrame = itr.next();
                            	 		AbstractInsnNode ldcNode = result.getMapping().get(ldcFrame);
                            	 		for(LabelNode label : ((TableSwitchInsnNode)ain).labels)
                            	 			if(label.getNext() != null && label.getNext().equals(ldcNode))
                            	 			{
                            	 				results.remove(Utils.getIntValue(ldcNode));
                            	 				itr.remove();
                            	 			}
                            	 	}
                                }
                                if (results.size() == 1) {
                                    TableSwitchInsnNode tsin = ((TableSwitchInsnNode) ain);
                                    int cst = results.iterator().next();
                                    LabelNode target = (cst < tsin.min || cst > tsin.max) ? tsin.dflt : tsin.labels.get(cst - tsin.min);
                                    InsnList replacement = new InsnList();
                                    replacement.add(new InsnNode(POP)); // remove existing args from stack
                                    replacement.add(new JumpInsnNode(GOTO, target));
                                    replacements.put(ain, replacement);
                                    folded.getAndIncrement();
                                }
                                break;
                            }
                            case IFGE:
                            case IFGT:
                            case IFLE:
                            case IFLT:
                            case IFNE:
                            case IFEQ: {
                                List<Frame> frames = result.getFrames().get(ain);
                                if (frames == null) {
                                    // wat
                                    break;
                                }
                                Set<Boolean> results = new HashSet<>();
                                for (Frame frame0 : frames) {
                                    JumpFrame frame = (JumpFrame) frame0;
                                    if (frame.getComparators().get(0) instanceof LdcFrame) {
                                        if (results.size() > 1) {
                                            break opcodes;
                                        }
                                    	int value = ((Number) ((LdcFrame) frame.getComparators().get(0)).getConstant()).intValue();
                                        switch (ainOpcode) {
                                            case IFGE:
                                                results.add(value >= 0);
                                                break;
                                            case IFGT:
                                                results.add(value > 0);
                                                break;
                                            case IFLE:
                                                results.add(value <= 0);
                                                break;
                                            case IFLT:
                                                results.add(value < 0);
                                                break;
                                            case IFNE:
                                                results.add(value != 0);
                                                break;
                                            case IFEQ:
                                                results.add(value == 0);
                                                break;
                                            default:
                                                throw new RuntimeException();
                                        }
                                    } else {
                                    	break opcodes;
	                                }
                                }
                                if (results.size() == 1) {
                                    InsnList replacement = new InsnList();
                                    replacement.add(new InsnNode(POP)); // remove existing args from stack
                                    if (results.iterator().next()) {
                                        replacement.add(new JumpInsnNode(GOTO, ((JumpInsnNode) ain).label));
                                    }
                                    replacements.put(ain, replacement);
                                    folded.getAndIncrement();
                                }
                                break;
                            }
                            case IF_ICMPLE:
                            case IF_ICMPGT:
                            case IF_ICMPGE:
                            case IF_ICMPLT:
                            case IF_ICMPNE:
                            case IF_ICMPEQ: {
                                List<Frame> frames = result.getFrames().get(ain);
                                if (frames == null) {
                                    // wat
                                    break;
                                }
                                Set<Boolean> results = new HashSet<>();
                                for (Frame frame0 : frames) {
                                    JumpFrame frame = (JumpFrame) frame0;
                                    if (frame.getComparators().get(0) instanceof LdcFrame && frame.getComparators().get(1) instanceof LdcFrame) {
                                        if (results.size() > 1) {
                                            break opcodes;
                                        }
                                    	int topValue = ((Number) ((LdcFrame) frame.getComparators().get(0)).getConstant()).intValue();
                                    	int bottomValue = ((Number) ((LdcFrame) frame.getComparators().get(1)).getConstant()).intValue();
                                        switch (ainOpcode) {
                                            case IF_ICMPNE:
                                                results.add(bottomValue != topValue);
                                                break;
                                            case IF_ICMPEQ:
                                                results.add(bottomValue == topValue);
                                                break;
                                            case IF_ICMPLT:
                                                results.add(bottomValue < topValue);
                                                break;
                                            case IF_ICMPGE:
                                                results.add(bottomValue >= topValue);
                                                break;
                                            case IF_ICMPGT:
                                                results.add(bottomValue > topValue);
                                                break;
                                            case IF_ICMPLE:
                                                results.add(bottomValue <= topValue);
                                                break;
                                            default:
                                                throw new RuntimeException();
                                        }
                                    } else {
                                        break opcodes;
                                    }
                                }
                                if (results.size() == 1) {
                                    InsnList replacement = new InsnList();
                                    replacement.add(new InsnNode(POP2)); // remove existing args from stack
                                    if (results.iterator().next()) {
                                        replacement.add(new JumpInsnNode(GOTO, ((JumpInsnNode) ain).label));
                                    }
                                    replacements.put(ain, replacement);
                                    folded.getAndIncrement();
                                }
                                break;
                            }
                            case DUP: {
                                List<Frame> frames = result.getFrames().get(ain);
                                if (frames == null) {
                                    // wat
                                    break;
                                }
                                Set<Object> results = new HashSet<>();
                                for (Frame frame0 : frames) {
                                    DupFrame frame = (DupFrame) frame0;
                                    if (frame.getTargets().get(0) instanceof LdcFrame) {
                                        results.add(((LdcFrame) frame.getTargets().get(0)).getConstant());
                                    } else {
                                        break opcodes;
                                    }
                                }
                                if (results.size() == 1) {
                                    Object val = results.iterator().next();
                                    InsnList replacement = new InsnList();
                                    if (val == null) {
                                        replacement.add(new InsnNode(ACONST_NULL));
                                    } else {
                                        replacement.add(new LdcInsnNode(val));
                                    }
                                    replacements.put(ain, replacement);
                                    folded.getAndIncrement();
                                }
                                break;
                            }
                            case POP:
                            case POP2: {
                                if (!getConfig().isExperimentalPopFolding()) {
                                    break;
                                }

                                List<Frame> frames = result.getFrames().get(ain);
                                if (frames == null) {
                                    // wat
                                    break;
                                }
                                Set<AbstractInsnNode> remove = new HashSet<>();
                                for (Frame frame0 : frames) {
                                    PopFrame frame = (PopFrame) frame0;
                                    if (frame.getRemoved().get(0) instanceof LdcFrame
                                        && (ainOpcode != POP2 || frame.getRemoved().size() == 2 && frame.getRemoved().get(1) instanceof LdcFrame)) {
                                        for (Frame deletedFrame : frame.getRemoved()) {
                                            if (deletedFrame.getChildren().size() > 1) {
                                                // ldc -> ldc -> swap -> pop = we can't even
                                                break opcodes;
                                            }
                                            remove.add(result.getMapping().get(deletedFrame));
                                        }
                                    } else {
                                    	if(frame.getRemoved().size() == 1)
                                    	{
                                    		//Load + pop
                                    		Frame removed = frame.getRemoved().get(0);
                                    		if(removed.getChildren().size() > 1 && removed.getChildren().indexOf(frame) - 1 >= 0
                                    			&& removed.getChildren().get(removed.getChildren().indexOf(frame) - 1) instanceof LocalFrame
                                    			&& removed.getChildren().get(removed.getChildren().indexOf(frame) - 1).getOpcode() >= ILOAD
                                    			&& removed.getChildren().get(removed.getChildren().indexOf(frame) - 1).getOpcode() <= ALOAD)
                                    			remove.add(result.getMapping().get(removed.getChildren().get(removed.getChildren().indexOf(frame) - 1)));
                                    		else
                                    			break opcodes;
                                    	}else if(frame.getRemoved().size() == 2)
                                    	{
                                    		//Load + load + pop2
                                    		Frame removed1 = frame.getRemoved().get(0);
                                    		Frame removed2 = frame.getRemoved().get(1);
                                    		if(removed1.equals(removed2) && removed1.getChildren().size() > 2 && removed1.getChildren().indexOf(frame) - 2 >= 0
                                    			&& removed1.getChildren().get(removed1.getChildren().indexOf(frame) - 1) instanceof LocalFrame
                                    			&& removed1.getChildren().get(removed1.getChildren().indexOf(frame) - 1).getOpcode() >= ILOAD
                                    			&& removed1.getChildren().get(removed1.getChildren().indexOf(frame) - 1).getOpcode() <= ALOAD
                                    			&& removed1.getChildren().get(removed1.getChildren().indexOf(frame) - 2) instanceof LocalFrame
                                    			&& removed1.getChildren().get(removed1.getChildren().indexOf(frame) - 2).getOpcode() >= ILOAD
                                    			&& removed1.getChildren().get(removed1.getChildren().indexOf(frame) - 2).getOpcode() <= ALOAD)
                                    		{
                                    			//Previous instruction loads the same thing (expected children: load, load, pop2)
                                    			remove.add(result.getMapping().get(removed1.getChildren().get(removed1.getChildren().indexOf(frame) - 1)));
                                    			remove.add(result.getMapping().get(removed1.getChildren().get(removed1.getChildren().indexOf(frame) - 2)));
                                    		}else if(removed1.getChildren().size() > 1 && removed2.getChildren().size() > 1 
                                    			&& removed1.getChildren().get(removed1.getChildren().indexOf(frame) - 1) instanceof LocalFrame
                                    			&& removed2.getChildren().get(removed2.getChildren().indexOf(frame) - 1) instanceof LocalFrame)
                                    		{
                                    			//Previous instruction is "load" and it loads different things
                                    			remove.add(result.getMapping().get(removed1.getChildren().get(removed1.getChildren().indexOf(frame) - 1)));
                                    			remove.add(result.getMapping().get(removed2.getChildren().get(removed2.getChildren().indexOf(frame) - 1)));
                                    		}else
                                    			break opcodes;
                                    	}else
                                    		break opcodes;
                                    }
                                }
                                for (AbstractInsnNode insn : remove) {
                                    replacements.put(insn, new InsnList());
                                    replacements.put(ain, new InsnList());
                                    folded.getAndIncrement();
                                }
                                break;
                            }
                            default:
                                break;
                        }
                    }

                    replacements.forEach((ain, replacement) -> {
                        methodNode.instructions.insertBefore(ain, replacement);
                        methodNode.instructions.remove(ain);
                    });
                } while (start != folded.get());
            });
        });
        System.out.println("Folded " + folded.get() + " constants");

        return folded.get() > 0;
    }

    public static class Config extends TransformerConfig {
        private boolean experimentalPopFolding;

        public Config() {
            super(ConstantFolder.class);
        }

        public boolean isExperimentalPopFolding() {
            return experimentalPopFolding;
        }

        public void setExperimentalPopFolding(boolean experimentalPopFolding) {
            this.experimentalPopFolding = experimentalPopFolding;
        }
    }
}
