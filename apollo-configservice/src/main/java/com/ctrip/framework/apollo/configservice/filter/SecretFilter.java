package com.ctrip.framework.apollo.configservice.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.ctrip.framework.apollo.biz.service.AppService;
import com.ctrip.framework.apollo.common.entity.App;

@WebFilter(urlPatterns="/configs/*,/configfiles/*")
public class SecretFilter implements Filter {
	private static final Logger logger = LoggerFactory.getLogger(SecretFilter.class);
	
	@Autowired
	private AppService appService;
	
	private Map<String, String> keyMap = new HashMap<String, String>();

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		//TODO 加载所有appid对应的secretkey
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		String requestURI = req.getRequestURI();
		String[] split = requestURI.split("/");
		String appId = split[1];
		String cluster = split[2];
		String namespace = split[3];
		
		String secretKey = keyMap.get(appId);
		if(secretKey == null) {
			App findOne = appService.findOne(appId);
			if(findOne != null) {
				secretKey = findOne.getSecretKey();
				keyMap.put(appId, secretKey);
			}
		}
		
		if(secretKey != null) {
			Map<String, String[]> parameterMap = req.getParameterMap();
			Map<String, String> hm = copyMap(parameterMap);
		  hm.put("appId", appId);
		  hm.put("cluster", cluster);
		  hm.put("namespace", namespace);
			 boolean signatureValid = false;
			try {
				signatureValid = SecretUtil.isSignatureValid(hm, secretKey, "sign");
			} catch (Exception e) {
				logger.error("验证请求签名过程中，计算签名时发生错误", e);
			}
			 if(signatureValid) {
				 doFilter(request, response, chain);
			 } else {
				 res.sendError(HttpStatus.SC_FORBIDDEN, "无权限");
			 }
			  
		}
	}
	
	
	private Map<String, String> copyMap(Map<String, String[]> parameterMap){
		HashMap<String, String> result = new HashMap<String, String>();
		
		Set<String> keySet = parameterMap.keySet();
		for (String key : keySet) {
			String[] strings = parameterMap.get(key);
			result.put(key, strings[0]);
		}		
		
		return result;
	}

	@Override
	public void destroy() {

	}

}
