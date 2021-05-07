package com.javadeobfuscator.deobfuscator.transformers.general.removers;

import java.util.Collection;

import com.javadeobfuscator.deobfuscator.config.TransformerConfig;
import com.javadeobfuscator.deobfuscator.transformers.Transformer;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

public class RuntimeInvisibleAnnotationRemover extends Transformer<TransformerConfig> {

	@Override
	public boolean transform() throws Throwable {
		boolean edit = false;
		for (ClassNode classNode : classNodes()) {
			if (notEmptyOrNull(classNode.invisibleAnnotations)) {
				edit = true;
				classNode.invisibleAnnotations = null;
			}
			if (notEmptyOrNull(classNode.invisibleTypeAnnotations)) {
				edit = true;
				classNode.invisibleTypeAnnotations = null;
			}
			for (MethodNode methodNode : classNode.methods) {
				if (notEmptyOrNull(methodNode.invisibleAnnotations)) {
					edit = true;
					methodNode.invisibleAnnotations = null;
				}
				if (notEmptyOrNull(methodNode.invisibleTypeAnnotations)) {
					edit = true;
					methodNode.invisibleTypeAnnotations = null;
				}
				if (notEmptyOrNull(methodNode.invisibleLocalVariableAnnotations)) {
					edit = true;
					methodNode.invisibleLocalVariableAnnotations = null;
				}
				if (notEmptyOrNull(methodNode.invisibleParameterAnnotations)) {
					edit = true;
					methodNode.invisibleParameterAnnotations = null;
				}
				if (notEmptyOrNull(methodNode.invisibleTypeAnnotations)) {
					edit = true;
					methodNode.invisibleTypeAnnotations = null;
				}
			}
			for (FieldNode fieldNode : classNode.fields) {
				if (notEmptyOrNull(fieldNode.invisibleAnnotations)) {
					edit = true;
					fieldNode.invisibleAnnotations = null;
				}
				if (notEmptyOrNull(fieldNode.invisibleTypeAnnotations)) {
					edit = true;
					fieldNode.invisibleTypeAnnotations = null;
				}
			}
		}
		return edit;
	}

	private static boolean notEmptyOrNull(Collection<?> c) {
		return c != null && !c.isEmpty();
	}

	private static boolean notEmptyOrNull(Collection<?>[] cs) {
		if (cs == null) {
			return false;
		}
		for (Collection<?> c : cs) {
			if (!c.isEmpty()) {
				return true;
			}
		}
		return false;
	}
}
